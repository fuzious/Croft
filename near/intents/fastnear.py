"""Paced client for the FastNEAR Transactions API (tx.main.fastnear.com, free, no key).

The API allows about 60 requests a minute per IP. One client paces every request at a fixed interval, backs off on
429 and transient errors, and raises `Refused` when the API keeps refusing for longer than `refuse_after` seconds,
so a bulk run can stop gracefully instead of hammering.
"""
from __future__ import annotations

import json
import time
from typing import Callable, Iterable

BASE = "https://tx.main.fastnear.com/v0"
USER_AGENT = "intents-collector/0.1"
TX_BATCH = 20
PAGE_LIMIT = 200

# transport(path, body) -> (status_code, headers, body_bytes)
Transport = Callable[[str, dict], tuple[int, dict, bytes]]


class Refused(RuntimeError):
    """FastNEAR kept refusing requests for longer than the client's refusal window."""


class Pacer:
    """Spaces request starts at least `interval` seconds apart; `penalize` pushes the next start further out."""

    def __init__(self, interval: float = 1.0, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.interval = interval
        self.clock = clock
        self.sleep = sleep
        self._next = 0.0

    def wait(self) -> None:
        now = self.clock()
        if self._next > now:
            self.sleep(self._next - now)
            now = self._next
        self._next = now + self.interval

    def penalize(self, seconds: float) -> None:
        self._next = max(self._next, self.clock() + seconds)


def backoff_delay(attempt: int, base: float = 5.0, cap: float = 120.0) -> float:
    """Delay before retry number `attempt` (0-based): base * 2**attempt, capped."""
    return min(cap, base * (2 ** attempt))


def retry_after(headers: dict) -> float | None:
    for k, v in headers.items():
        if k.lower() == "retry-after":
            try:
                return max(0.0, float(v))
            except (TypeError, ValueError):
                return None
    return None


def httpx_transport(timeout: float = 60.0) -> Transport:
    import httpx

    client = httpx.Client(timeout=timeout, headers={"user-agent": USER_AGENT, "content-type": "application/json"})

    def send(path: str, body: dict) -> tuple[int, dict, bytes]:
        r = client.post(BASE + path, content=json.dumps(body))
        return r.status_code, dict(r.headers), r.content

    return send


def unique(items: Iterable[str]) -> list[str]:
    """Order-preserving dedupe."""
    return list(dict.fromkeys(items))


def tx_hash(tx: dict) -> str:
    return tx["transaction"]["hash"]


def dedupe_txs(txs: Iterable[dict | None], seen: set[str] | None = None) -> list[dict]:
    """Drop None entries and repeated hashes (also those already in `seen`, which is updated)."""
    seen = set() if seen is None else seen
    out = []
    for t in txs:
        if not t:
            continue
        h = tx_hash(t)
        if h in seen:
            continue
        seen.add(h)
        out.append(t)
    return out


class FastNear:
    def __init__(self, transport: Transport | None = None, pacer: Pacer | None = None, max_tries: int = 8,
                 refuse_after: float = 900.0, log: Callable[[str], None] | None = None):
        self.transport = transport or httpx_transport()
        self.pacer = pacer or Pacer()
        self.max_tries = max_tries
        self.refuse_after = refuse_after
        self.log = log or (lambda msg: None)
        self.stats = {"requests": 0, "ok": 0, "http_429": 0, "http_err": 0, "net_err": 0, "retries": 0}
        self._failing_since: float | None = None

    def _failed(self, attempt: int, hint: float | None) -> None:
        now = self.pacer.clock()
        if self._failing_since is None:
            self._failing_since = now
        if now - self._failing_since >= self.refuse_after:
            raise Refused(f"FastNEAR refusing for {now - self._failing_since:.0f}s; stats={self.stats}")
        self.stats["retries"] += 1
        self.pacer.penalize(hint if hint is not None else backoff_delay(attempt))

    def post(self, path: str, body: dict) -> dict:
        for attempt in range(self.max_tries):
            self.pacer.wait()
            self.stats["requests"] += 1
            try:
                status, headers, raw = self.transport(path, body)
            except Exception as e:  # network errors: timeouts, resets
                self.stats["net_err"] += 1
                self.log(f"net error {path}: {e!r}")
                self._failed(attempt, None)
                continue
            if status == 200:
                self.stats["ok"] += 1
                self._failing_since = None
                return json.loads(raw)
            if status == 429:
                self.stats["http_429"] += 1
                self.log(f"429 {path} attempt={attempt}")
                self._failed(attempt, retry_after(headers))
                continue
            self.stats["http_err"] += 1
            self.log(f"HTTP {status} {path}: {raw[:200]!r}")
            if 400 <= status < 500:
                raise RuntimeError(f"HTTP {status} {path}: {raw[:200]!r}")
            self._failed(attempt, None)
        raise RuntimeError(f"gave up on {path} after {self.max_tries} tries")

    def account_page(self, account_id: str, **query) -> dict:
        body = {"account_id": account_id, "limit": PAGE_LIMIT}
        body.update({k: v for k, v in query.items() if v is not None})
        return self.post("/account", body)

    def transactions(self, hashes: Iterable[str]) -> list[dict]:
        """Full transactions for `hashes`, deduped, in API order per batch of 20. Missing hashes are skipped."""
        hashes = unique(hashes)
        seen: set[str] = set()
        out: list[dict] = []
        for i in range(0, len(hashes), TX_BATCH):
            d = self.post("/transactions", {"tx_hashes": hashes[i:i + TX_BATCH]})
            out += dedupe_txs(d.get("transactions") or [], seen)
        return out
