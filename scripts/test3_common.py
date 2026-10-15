"""Shared plumbing for sealed test set v3: traces/replays stored like build_dataset.replay_and_store.

polygon, optimism: exact on-chain execution via keyed dRPC debug_traceTransaction (callTracer withLog) +
                   the real receipt logs  (source = "mainnet_trace").
arbitrum:          dRPC/Alchemy serve no traces -> anvil fork replay from Alchemy archive state with the
                   unmodified oracle.replay.Replayer (kept only if status + log count match mainnet).
"""
import itertools
import os
import json
import threading
from pathlib import Path

import test3_chains as tc  # noqa: F401  (installs runtime chain config)
from oracle import sources
from oracle.replay import Replayer
from oracle.sources import Alchemy, Etherscan

ROOT = Path(__file__).resolve().parents[1]
REPLAYS = ROOT / "data" / "replays"
TRACE_CHAINS = {"polygon", "optimism"}
ETHERSCAN_LIMIT = sources.RateLimiter(float(os.environ.get("TEST3_ES_RATE", "2.5")))  # one budget for this whole process (other jobs share the key)

_local = threading.local()
_lock = threading.Lock()
_ports = itertools.count(int(os.environ.get("TEST3_PORT_BASE", "9500")))
_clients: dict = {}
_all_replayers: list = []


def etherscan(chain: str) -> Etherscan:
    with _lock:
        if ("es", chain) not in _clients:
            e = Etherscan(chain)
            e.limit = ETHERSCAN_LIMIT
            _clients[("es", chain)] = e
        return _clients[("es", chain)]


def alchemy(chain: str, key: int = 0) -> Alchemy:
    with _lock:
        if ("al", chain, key) not in _clients:
            _clients[("al", chain, key)] = Alchemy(chain, key=key)
        return _clients[("al", chain, key)]


def drpc(chain: str):
    with _lock:
        if ("dr", chain) not in _clients:
            _clients[("dr", chain)] = tc.Drpc3(chain)
        return _clients[("dr", chain)]


def replayer(chain: str) -> Replayer:
    rps = getattr(_local, "rps", None)
    if rps is None:
        rps = _local.rps = {}
    if chain not in rps:
        with _lock:
            port = next(_ports)
        al = alchemy(chain, key=port % 2)  # alternate the two Alchemy keys across workers
        rps[chain] = Replayer(port=port, alchemy=al, upstream=al.url)
        _all_replayers.append(rps[chain])
    return rps[chain]


def trace_direct(chain: str, h: str) -> dict | None:
    if chain not in TRACE_CHAINS:
        return None
    al = alchemy(chain)
    tx = al.tx(h)
    if tx is None:
        raise LookupError(f"{h} not found")
    receipt = al.receipt(h)
    try:
        trace = drpc(chain).rpc("debug_traceTransaction",
                                [h, {"tracer": "callTracer", "tracerConfig": {"withLog": True}}], cache=False)
    except RuntimeError:
        return None
    status = int(receipt["status"], 16)
    return {"tx_hash": h, "tx": tx, "block": al.block(int(tx["blockNumber"], 16)), "ok": status == 1,
            "matched": True, "orig_status": status, "trace": trace, "logs": receipt["logs"], "error": None,
            "source": "mainnet_trace"}


def replay_and_store(chain: str, h: str) -> dict | None:
    path = REPLAYS / f"{h}.json"
    if path.exists():
        return json.loads(path.read_text())
    rec = trace_direct(chain, h)
    if rec is None:
        if chain in TRACE_CHAINS:
            return None  # trace endpoint failed: do not fall back to a (less exact) replay on trace chains
        r = replayer(chain).replay(h)
        rec = {"tx_hash": h, "tx": r.tx, "block": r.block, "ok": r.ok, "matched": r.matched,
               "orig_status": r.orig_status, "trace": r.trace, "logs": r.logs, "error": r.error,
               "source": "anvil_replay"}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rec))
    return rec


def close_replayers():
    for rp in _all_replayers:
        try:
            rp.close()
        except Exception:  # noqa: BLE001
            pass
