"""Shared plumbing for the user-harm / NFT / vault collection (scripts/harm_*.py).

Exclusion set, clients (Alchemy key 1, shared low-rate Etherscan), log decoding, and exact mainnet traces
stored like build_dataset.replay_and_store does (data/replays/<hash>.json, source="mainnet_trace").
Never falls back to anvil replays: a row is kept only if its dRPC trace is ok and matched.
"""
import json
import re
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_dataset as bd  # noqa: E402
from oracle import sources  # noqa: E402
from oracle.sources import Alchemy, Etherscan  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
REPLAYS = DATA / "replays"
HASH = re.compile(r"0x[0-9a-fA-F]{64}")

bd.configure("eth")
bd.alchemy = Alchemy("eth", key=1)  # prefer key 1 (trace_direct reads the module global)
alchemy = bd.alchemy
etherscan = Etherscan("eth")
etherscan.limit = sources.RateLimiter(2.5)  # Etherscan is shared with other jobs
bd.etherscan = etherscan

T_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
T_SINGLE = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
T_BATCH = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb"
T_APPROVAL_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
ZERO = "0x" + "0" * 40


def used_hashes() -> set[str]:
    """Every 32-byte hex in data/*.jsonl|*.json (except harm_*), data/cards/**/*.jsonl, models/*_tx_hashes.json."""
    files = [p for p in DATA.glob("*.jsonl") if not p.name.startswith("harm_")]
    files += list(DATA.glob("*.json")) + list((DATA / "cards").rglob("*.jsonl"))
    files += list((ROOT / "models").glob("*_tx_hashes.json"))
    out: set[str] = set()
    for f in files:
        out.update(h.lower() for h in HASH.findall(f.read_text(errors="ignore")))
    return out


def addr_topic(t: str) -> str:
    return "0x" + t[-40:].lower()


def transfers(logs: list) -> list[dict]:
    """ERC-20 / ERC-721 / ERC-1155 transfers: {std, token, from, to, amount|id}."""
    out = []
    for lg in logs:
        tp = lg.get("topics") or []
        if not tp:
            continue
        t0, token, data = tp[0].lower(), lg["address"].lower(), lg.get("data") or "0x"
        if t0 == T_TRANSFER and len(tp) == 3 and len(data) >= 66:
            out.append({"std": "erc20", "token": token, "from": addr_topic(tp[1]), "to": addr_topic(tp[2]),
                        "amount": int(data[2:66], 16)})
        elif t0 == T_TRANSFER and len(tp) == 4:
            out.append({"std": "erc721", "token": token, "from": addr_topic(tp[1]), "to": addr_topic(tp[2]),
                        "id": int(tp[3], 16), "amount": 1})
        elif t0 == T_SINGLE and len(tp) == 4 and len(data) >= 130:
            out.append({"std": "erc1155", "token": token, "from": addr_topic(tp[2]), "to": addr_topic(tp[3]),
                        "id": int(data[2:66], 16), "amount": int(data[66:130], 16)})
        elif t0 == T_BATCH and len(tp) == 4:
            out.append({"std": "erc1155", "token": token, "from": addr_topic(tp[2]), "to": addr_topic(tp[3]),
                        "id": None, "amount": 1})
    return out


def eth_value_calls(trace: dict) -> list[tuple[str, str, int]]:
    """(from, to, wei) for every value-carrying call frame in a callTracer trace."""
    out, stack = [], [trace]
    while stack:
        fr = stack.pop()
        v = int(fr.get("value") or "0x0", 16)
        if v and fr.get("type") not in ("DELEGATECALL", "STATICCALL"):
            out.append(((fr.get("from") or "").lower(), (fr.get("to") or "").lower(), v))
        stack.extend(fr.get("calls") or [])
    return out


def code(addr: str) -> str:
    return alchemy.rpc("eth_getCode", [addr, "latest"])


def is_eoa(addr: str) -> bool:
    c = code(addr)
    return c in ("0x", "") or c.lower().startswith("0xef0100")  # EIP-7702 delegated EOAs count as EOAs


_trace_lock = threading.Lock()


def trace(h: str) -> dict | None:
    """Exact mainnet trace (dRPC callTracer + receipt logs) stored at data/replays/<h>.json; None if unavailable."""
    path = REPLAYS / f"{h}.json"
    if path.exists():
        rec = json.loads(path.read_text())
        if rec.get("ok") and rec.get("matched"):
            return rec
        if rec.get("source") == "mainnet_trace":
            return rec
    rec = bd.trace_direct(h)
    if rec is None:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(rec))
    tmp.replace(path)
    return rec


def month_of(block: int) -> str:
    import datetime as dt
    ts = int(alchemy.block(block)["timestamp"], 16)
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m")


def append(path: Path, row: dict, lock=threading.Lock()):
    with lock:
        with path.open("a") as fh:
            fh.write(json.dumps(row) + "\n")
