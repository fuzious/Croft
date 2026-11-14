"""NEAR Intents transaction scoring for the oracle: fetch transactions from the FastNEAR Transactions API (mainnet,
free, no key) and score them with the frozen intents model (near.intents.model.score_tx, near/models/intents_v1.*).

- `score_hash(tx_hash)`: one transaction, for POST /v1/intents/score.
- `activity_signal(receiver_id)`: the receiver's most recent transactions that touch intents.near, scored, for the
  intents_activity signal of /v1/check. It reads the receiver's account index (newest first, THRESHOLDS
  ["intents_index_rows"] rows), then full transactions in batches of 20 until THRESHOLDS["intents_recent_txs"] Intents
  txs are found, using at most THRESHOLDS["intents_max_requests"] requests. Successful reads are cached per receiver
  for THRESHOLDS["intents_cache_s"], at most CACHE_ENTRIES receivers (least recently read evicted first).

FastNEAR requests go through near.intents.fastnear with one try each, and each one ends within TIMEOUT_S of
wall-clock time however slowly FastNEAR sends (see transport), so a slow or rate-limiting FastNEAR is reported, never
retried for minutes. An activity read makes at most THRESHOLDS["intents_max_requests"] sequential requests, so it ends
within that many x TIMEOUT_S; /v1/check stops waiting after near.service.app.INTENTS_DEADLINE_S. FastNEAR data is
untrusted: any failure to read, parse or score it, and a /transactions answer missing any requested transaction,
makes the signal unavailable (which the policy turns into a warn)."""
from __future__ import annotations

import json
import math
import threading
import time
from collections import OrderedDict
from pathlib import Path

import httpcore

from near.intents.fastnear import BASE, USER_AGENT, FastNear, Pacer, Transport, unique
from near.intents.features import KNOWN_INTENTS_IDS

from .policy import THRESHOLDS
from .signals import sig

MODEL_JSON = Path(__file__).resolve().parents[1] / "models" / "intents_v1.json"
TIMEOUT_S = 6.0                         # wall-clock limit of one FastNEAR request
MAX_ANSWER_BYTES = 8 * 2**20            # larger FastNEAR answers are refused; the largest recorded batch is 1.7 MB
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SOURCE = "fastnear:/v0/account + /v0/transactions, near/models/intents_v1"
CACHE_ENTRIES = 1024
TRANSPORT: Transport | None = None      # set lazily to transport(); tests swap in recorded responses
_cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
_lock = threading.Lock()
_request = threading.local()            # .deadline: time.monotonic() by which this thread's FastNEAR request ends


class FastNearError(Exception):
    """FastNEAR could not be read (network error, HTTP error, rate limit or a non-JSON body)."""


class FastNearTimeout(FastNearError):
    """A FastNEAR request did not end within its TIMEOUT_S deadline."""


class TxNotFound(Exception):
    pass


class ModelUnavailable(Exception):
    """The frozen intents model is missing or refused by its hash checks."""


class TxUnscorable(Exception):
    """A transaction fetched from FastNEAR has a shape the intents model cannot score."""


def _left(timeout: float | None) -> float:
    """Seconds one network operation of this thread's FastNEAR request may block: `timeout`, cut to what is left
    before the request's deadline. Raises TimeoutError once the deadline has passed."""
    left = getattr(_request, "deadline", math.inf) - time.monotonic()
    if left <= 0:
        raise TimeoutError("FastNEAR request deadline passed")
    return left if timeout is None else min(timeout, left)


class _DeadlineStream(httpcore.NetworkStream):
    """A network stream whose every read, write and TLS handshake blocks at most until the request's deadline."""

    def __init__(self, stream: httpcore.NetworkStream):
        self.stream = stream

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self.stream.read(max_bytes, _left(timeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.stream.write(buffer, _left(timeout))

    def close(self) -> None:
        self.stream.close()

    def start_tls(self, ssl_context, server_hostname: str | None = None, timeout: float | None = None):
        return _DeadlineStream(self.stream.start_tls(ssl_context, server_hostname, _left(timeout)))

    def get_extra_info(self, info: str):
        return self.stream.get_extra_info(info)


class _DeadlineBackend(httpcore.NetworkBackend):
    def __init__(self):
        self.backend = httpcore.SyncBackend()

    def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None,
                    socket_options=None) -> httpcore.NetworkStream:
        return _DeadlineStream(self.backend.connect_tcp(host, port, _left(timeout), local_address, socket_options))

    def sleep(self, seconds: float) -> None:
        self.backend.sleep(seconds)


def transport(base: str = BASE, timeout: float = TIMEOUT_S, max_bytes: int = MAX_ANSWER_BYTES) -> Transport:
    """(path, body) -> (status, headers, bytes) over httpcore. Each request ends within `timeout` seconds of
    wall-clock time, however slowly the server sends its status line, headers or body: every connect, TLS handshake,
    read and write blocks only until that deadline (DNS resolution is not covered). Past it the request raises
    TimeoutError; an answer over `max_bytes` raises ValueError."""
    pool = httpcore.ConnectionPool(network_backend=_DeadlineBackend())
    headers = [(b"user-agent", USER_AGENT.encode()), (b"content-type", b"application/json")]
    phases = {"connect": timeout, "read": timeout, "write": timeout, "pool": timeout}

    def send(path: str, body: dict) -> tuple[int, dict, bytes]:
        _request.deadline = time.monotonic() + timeout
        try:
            with pool.stream("POST", base.rstrip("/") + path, headers=headers, content=json.dumps(body).encode(),
                             extensions={"timeout": phases}) as r:
                raw = bytearray()
                for chunk in r.iter_stream():
                    raw += chunk
                    if len(raw) > max_bytes:
                        raise ValueError(f"FastNEAR answer is larger than {max_bytes} bytes")
                return r.status, {k.decode("latin-1"): v.decode("latin-1") for k, v in r.headers}, bytes(raw)
        except (TimeoutError, httpcore.TimeoutException):
            raise TimeoutError(f"FastNEAR did not answer within {timeout:g} s") from None
        finally:
            _request.deadline = math.inf

    return send


def _transport(t: Transport | None) -> Transport:
    global TRANSPORT
    if t is not None:
        return t
    if TRANSPORT is None:
        TRANSPORT = transport()
    return TRANSPORT


class _Client:
    """near.intents.fastnear.FastNear with one try per request; any failure raises FastNearError with the reason,
    FastNearTimeout when the transport timed out."""

    def __init__(self, t: Transport | None):
        self.log: list[str] = []
        self.timed_out: str | None = None
        send = _transport(t)

        def timed(path: str, body: dict) -> tuple[int, dict, bytes]:
            try:
                return send(path, body)
            except TimeoutError as e:
                self.timed_out = str(e)
                raise

        self.fn = FastNear(timed, pacer=Pacer(0.0), max_tries=1, refuse_after=0.0, log=self.log.append)
        self.requests = 0

    def _call(self, f, *a, **kw):
        self.requests += 1
        try:
            return f(*a, **kw)
        except Exception as e:  # Refused, RuntimeError (HTTP 4xx), ValueError (non-JSON body)
            if self.timed_out:
                raise FastNearTimeout(self.timed_out[:240]) from None
            why = self.log[-1] if self.log else f"{type(e).__name__}: {e}"
            raise FastNearError(f"FastNEAR request failed: {why[:240]}") from None

    def account_page(self, account_id: str, **q) -> dict:
        page = self._call(self.fn.account_page, account_id, **q)
        if not isinstance(page, dict) or not isinstance(page.get("account_txs"), list):
            raise FastNearError("FastNEAR account response is missing an account_txs list")
        if any(not isinstance(row, dict) or not valid_tx_hash(row.get("transaction_hash"))
               for row in page["account_txs"]):
            raise FastNearError("FastNEAR account response contains an invalid transaction hash")
        return page

    def transactions(self, hashes: list[str]) -> list[dict]:
        # Validate before the collector's permissive missing-row handling can hide a malformed response.
        body = self._call(self.fn.post, "/transactions", {"tx_hashes": hashes})
        if not isinstance(body, dict) or not isinstance(body.get("transactions"), list):
            raise FastNearError("FastNEAR response is missing a transactions list")
        by_hash = {}
        for tx in body["transactions"]:
            if tx is None:  # FastNEAR uses null for an unknown hash.
                continue
            if not isinstance(tx, dict) or not isinstance(tx.get("transaction"), dict):
                raise FastNearError("FastNEAR response contains a malformed transaction")
            h = tx["transaction"].get("hash")
            if not isinstance(h, str) or h not in hashes:
                raise FastNearError("FastNEAR returned a transaction that was not requested")
            _validate_receipt_graph(tx)
            # FastNEAR repeats an in-flight tx with the receipts seen so far; the fullest copy hides the least evidence.
            if h not in by_hash or len(tx["receipts"]) > len(by_hash[h]["receipts"]):
                by_hash[h] = tx
        return list(by_hash.values())


def _validate_receipt_graph(tx: dict) -> None:
    """Missing outcomes must not erase the failed callback or credit/refund evidence from a score."""
    try:
        receipts = tx["receipts"]
        if not isinstance(receipts, list):
            raise ValueError()
        ids = {row["receipt"]["receipt_id"] for row in receipts}
        if len(ids) != len(receipts) or any(not isinstance(rid, str) for rid in ids):
            raise ValueError()
        for outcome in _outcomes(tx):
            if not isinstance(outcome["receipt_ids"], list) or not isinstance(outcome["logs"], list):
                raise ValueError()
            if not isinstance(outcome["status"], dict) or not outcome["status"]:
                raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise TxUnscorable("FastNEAR transaction could not be scored (incomplete receipt graph)") from None


def _outcomes(tx: dict) -> list[dict]:
    return [tx["execution_outcome"]["outcome"], *(row["execution_outcome"]["outcome"] for row in tx["receipts"])]


def receipts_complete(tx: dict) -> bool:
    """True when every receipt an outcome spawned is in the tx (validated by _validate_receipt_graph). FastNEAR leaves
    out some receipts that intents.near spawns; a missing receipt can only hide evidence, so the label is a lower
    bound when this is False."""
    ids = {row["receipt"]["receipt_id"] for row in tx["receipts"]}
    return all(rid in ids for outcome in _outcomes(tx) for rid in outcome["receipt_ids"])


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def valid_tx_hash(h) -> bool:
    """A NEAR transaction hash: base58 of exactly 32 bytes."""
    if not isinstance(h, str) or not 32 <= len(h) <= 44 or any(c not in B58 for c in h):
        return False
    return len(b58decode(h)) == 32


def touches_intents(tx: dict, ids=KNOWN_INTENTS_IDS) -> bool:
    """True if the transaction or any of its receipts is sent to or by an Intents contract (FastNEAR shape)."""
    t = tx.get("transaction") or {}
    if t.get("receiver_id") in ids or t.get("signer_id") in ids:
        return True
    for x in tx.get("receipts") or []:
        rc = x.get("receipt") or {}
        if rc.get("receiver_id") in ids or rc.get("predecessor_id") in ids:
            return True
    return False


def model_info() -> dict:
    """{version, sha256} of the frozen intents model (sha256 of its pkl, from the manifest). Raises ModelUnavailable."""
    try:
        man = json.loads(MODEL_JSON.read_text())
        return {"version": man["version"], "sha256": man["pkl_sha256"]}
    except Exception as e:
        raise ModelUnavailable(f"intents model unavailable: {type(e).__name__}: {e}") from None


def score(tx: dict) -> dict:
    """near.intents.model.score_tx. Raises ModelUnavailable if the frozen model does not load, TxUnscorable if `tx`
    (untrusted FastNEAR data) has a shape the model cannot score; the reason names the error type only."""
    try:
        from near.intents.model import default_artifact, score_tx

        art = default_artifact()
    except Exception as e:
        raise ModelUnavailable(f"intents model unavailable: {type(e).__name__}: {e}") from None
    try:
        return score_tx(tx, art)
    except Exception as e:
        raise TxUnscorable(f"FastNEAR transaction could not be scored ({type(e).__name__})") from None


def _senders(tx: dict) -> set[str]:
    t = tx.get("transaction") or {}
    out = {t.get("signer_id")}
    for a in t.get("actions") or []:
        if isinstance(a, dict) and "Delegate" in a:
            out.add(((a["Delegate"] or {}).get("delegate_action") or {}).get("sender_id"))
    return out - {None}


def score_hash(tx_hash: str, sender_id: str | None = None, transport: Transport | None = None) -> dict:
    """Fetch one transaction through FastNEAR (one request, so it ends within TIMEOUT_S) and score it. Raises
    FastNearTimeout, FastNearError, TxNotFound, ModelUnavailable, TxUnscorable."""
    txs = _Client(transport).transactions([tx_hash])
    tx = next((x for x in txs if (x.get("transaction") or {}).get("hash") == tx_hash), None)
    if tx is None:
        raise TxNotFound(f"transaction {tx_hash} not found in FastNEAR (mainnet only)")
    r = score(tx)
    try:
        t = tx["transaction"]
        out = {"tx_hash": tx_hash, "signer_id": t.get("signer_id"), "receiver_id": t.get("receiver_id"),
               "risk": r["risk"], "label": r["label"], "rule_hits": r["rule_hits"], "flow_type": r["flow"],
               "top_features": r["top_features"], "anomaly_score": round(r["anomaly_score"], 6),
               "anomaly_percentile": round(r["anomaly_percentile"], 6), "touches_intents": touches_intents(tx),
               "receipts_complete": receipts_complete(tx)}
        if sender_id is not None:
            out["sender_id"] = sender_id
            out["sender_matches"] = sender_id in _senders(tx)
    except Exception as e:  # signer, actions or receipts of an unexpected shape
        raise TxUnscorable(f"FastNEAR transaction could not be scored ({type(e).__name__})") from None
    return out


def _brief(tx: dict, r: dict) -> dict:
    rules = [h["rule"] for h in r["rule_hits"] if h.get("severity") in ("high", "medium")]
    return {"tx_hash": tx["transaction"]["hash"], "label": r["label"], "risk": r["risk"], "flow": r["flow"],
            "rules": rules, "receipts_complete": receipts_complete(tx)}


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def activity_signal(receiver_id: str, transport: Transport | None = None, now: float | None = None) -> dict:
    """intents_activity signal: {n_scored, n_index_rows, requests, txs: [{tx_hash, label, risk, flow, rules,
    receipts_complete}]}, or unavailable (value None) with the reason when FastNEAR cannot be read, parsed or scored,
    or leaves out any requested transaction. Only successful reads are cached."""
    now = time.time() if now is None else now
    th = THRESHOLDS
    with _lock:
        hit = _cache.get(receiver_id)
        if hit and hit[0] > now:
            _cache.move_to_end(receiver_id)
            return hit[1]
    c = _Client(transport)
    try:
        page = c.account_page(receiver_id, desc=True, limit=th["intents_index_rows"])
        hashes = unique(r["transaction_hash"] for r in page.get("account_txs") or [])
        found: list[dict] = []
        for i in range(0, len(hashes), 20):
            if len(found) >= th["intents_recent_txs"] or c.requests >= th["intents_max_requests"]:
                break
            batch = hashes[i:i + 20]
            got = c.transactions(batch)
            k = len({x["transaction"]["hash"] for x in got} & set(batch))
            if k < len(batch):   # FastNEAR answers null for a hash it cannot serve; a partial read is not complete
                raise FastNearError(f"FastNEAR returned {k} of {len(batch)} transactions")
            found += [x for x in got if touches_intents(x)]
        rank = {h: i for i, h in enumerate(hashes)}   # index order: newest first; /transactions does not keep it
        found.sort(key=lambda x: rank.get(x["transaction"]["hash"], len(rank)))
        txs = [_brief(x, score(x)) for x in found[:th["intents_recent_txs"]]]
    except (FastNearError, ModelUnavailable, TxUnscorable) as e:
        return sig(None, SOURCE, False, str(e))
    except Exception as e:  # an HTTP 200 body of an unexpected shape
        return sig(None, SOURCE, False, f"FastNEAR response has an unexpected shape ({type(e).__name__})")
    out = sig({"n_scored": len(txs), "n_index_rows": len(hashes), "requests": c.requests, "txs": txs}, SOURCE)
    with _lock:
        _cache[receiver_id] = (now + th["intents_cache_s"], out)
        _cache.move_to_end(receiver_id)
        while len(_cache) > CACHE_ENTRIES:
            _cache.popitem(last=False)
    return out
