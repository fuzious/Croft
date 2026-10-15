"""Shared plumbing for sealed test set v4: exclusion set, clients, trace/replay storage.

Trace/replay records have the same shape as build_dataset.replay_and_store writes to data/replays/<hash>.json:
  eth/base (+ new chains where dRPC serves debug_traceTransaction): exact on-chain execution
      (callTracer withLog + real receipt logs, source="mainnet_trace");
  otherwise: anvil fork replay with the unmodified oracle.replay.Replayer (source="anvil_replay";
      usable only if ok and matched = same status + log count as on-chain).
"""
import itertools
import json
import os
import re
import threading
from pathlib import Path

import test4_chains as tc
from oracle import sources
from oracle.replay import Replayer
from oracle.sources import Alchemy, Drpc, Etherscan

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
REPLAYS = DATA / "replays"
HASH = re.compile(r"0x[0-9a-fA-F]{64}")
ES_LIMIT = sources.RateLimiter(float(os.environ.get("TEST4_ES_RATE", "2.0")))  # Etherscan shared with other jobs

_lock = threading.Lock()
_local = threading.local()
_clients: dict = {}
_ports = itertools.count(int(os.environ.get("TEST4_PORT_BASE", "9700")))
_all_replayers: list = []


def used_hashes() -> set[str]:
    """Every 32-byte hex string in existing data/*.jsonl|*.json (excluding test4_*), data/cards/**/*.jsonl and
    models/*_tx_hashes.json. Hash membership only (conservative: any 32-byte hex counts)."""
    files = [p for p in DATA.glob("*.jsonl") if not p.name.startswith("test4_")]
    files += [p for p in DATA.glob("*.json")]
    files += list((DATA / "cards").rglob("*.jsonl"))
    files += list((ROOT / "models").glob("*_tx_hashes.json"))
    out: set[str] = set()
    for f in files:
        out.update(h.lower() for h in HASH.findall(f.read_text(errors="ignore")))
    return out


def preexisting_replays() -> set[str]:
    return {p.stem.lower() for p in REPLAYS.glob("0x*.json")}


def etherscan(chain: str) -> Etherscan:
    with _lock:
        if ("es", chain) not in _clients:
            e = Etherscan(chain)
            e.limit = ES_LIMIT
            _clients[("es", chain)] = e
        return _clients[("es", chain)]


def rpc(chain: str) -> Alchemy:
    """tx/receipt/block client (same cache namespaces as the rest of the project for eth/bsc/base)."""
    with _lock:
        if ("rpc", chain) not in _clients:
            if chain in ("eth", "bsc", "base") or tc.RPC.get(chain) == "alchemy":
                _clients[("rpc", chain)] = Alchemy(chain, key=int(os.environ.get("TEST4_ALCHEMY_KEY", "1")))
            elif tc.RPC.get(chain) == "public":
                _clients[("rpc", chain)] = tc.Public4(chain)
            else:
                _clients[("rpc", chain)] = tc.Drpc4(chain)
        return _clients[("rpc", chain)]


def drpc(chain: str):
    with _lock:
        if ("dr", chain) not in _clients:
            if chain in ("eth", "bsc", "base"):
                _clients[("dr", chain)] = Drpc(chain)
            elif tc.TRACE.get(chain) == "public":
                _clients[("dr", chain)] = tc.Public4(chain)
            else:
                _clients[("dr", chain)] = tc.Drpc4(chain)
        return _clients[("dr", chain)]


TRACE_CHAINS = {"eth", "base"} | set(tc.TRACE)  # exact traces; everything else is anvil-replayed


def set_trace_chains(chains):
    TRACE_CHAINS.update(chains)


def upstream(chain: str, port: int) -> str:
    if chain == "bsc":  # public archive node (Alchemy BSC is throttled by other jobs sharing the keys)
        ups = [os.environ.get("TEST4_BSC_UPSTREAM", "https://bsc-mainnet.public.blastapi.io"), rpc("bsc").url]
        return ups[port % 2]
    return rpc(chain).url


def replayer(chain: str) -> Replayer:
    rps = getattr(_local, "rps", None)
    if rps is None:
        rps = _local.rps = {}
    if chain not in rps:
        with _lock:
            port = next(_ports)
        rps[chain] = Replayer(port=port, alchemy=rpc(chain), upstream=upstream(chain, port))
        _all_replayers.append(rps[chain])
    return rps[chain]


def trace_direct(chain: str, h: str) -> dict | None:
    if chain not in TRACE_CHAINS:
        return None
    al = rpc(chain)
    tx = al.tx(h)
    if tx is None:
        raise LookupError(f"{h} not found")
    receipt = al.receipt(h)
    try:
        trace = drpc(chain).rpc("debug_traceTransaction",
                                [h, {"tracer": "callTracer", "tracerConfig": {"withLog": True}}], cache=False)
    except RuntimeError:
        return None
    if not isinstance(trace, dict) or not trace.get("type"):
        return None
    status = int(receipt["status"], 16)
    return {"tx_hash": h, "tx": tx, "block": al.block(int(tx["blockNumber"], 16)), "ok": status == 1,
            "matched": True, "orig_status": status, "trace": trace, "logs": receipt["logs"], "error": None,
            "source": "mainnet_trace"}


def replay_and_store(chain: str, h: str, allow_replay: bool = True) -> dict | None:
    """Return a stored record (existing usable file, else exact trace, else anvil replay)."""
    path = REPLAYS / f"{h}.json"
    if path.exists():
        cached = json.loads(path.read_text())
        if cached.get("ok") and cached.get("matched"):
            return cached
        if cached.get("source") == "mainnet_trace" or chain not in TRACE_CHAINS:
            if not allow_replay or cached.get("source") == "mainnet_trace":
                return cached
    rec = trace_direct(chain, h)
    if rec is None:
        if chain in TRACE_CHAINS or not allow_replay:
            return None
        r = replayer(chain).replay(h)
        rec = {"tx_hash": h, "tx": r.tx, "block": r.block, "ok": r.ok, "matched": r.matched,
               "orig_status": r.orig_status, "trace": r.trace, "logs": r.logs, "error": r.error,
               "source": "anvil_replay"}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(rec))
    tmp.replace(path)
    return rec


def close_replayers():
    for rp in _all_replayers:
        try:
            rp.close()
        except Exception:  # noqa: BLE001
            pass
