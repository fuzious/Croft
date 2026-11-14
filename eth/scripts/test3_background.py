"""Sealed test v3 background normals (label 0): successful txs to *verified* contracts from random blocks
(same recipe as build_background.py) on polygon (2020-11+), arbitrum (post-Nitro) and optimism (post-Bedrock).
Only trace/replay here; cards are built by test3_cards.py.

    TEST3_ES_RATE=1.5 uv run python scripts/test3_background.py --chain polygon --n 300 --workers 3
Writes data/test3_bg_<chain>.jsonl (appends; resumable).
"""
import argparse
import json
import random
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test3_common as cm  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
BLOCK_LO = {"polygon": 10_000_000, "arbitrum": 22_300_000, "optimism": 105_300_000}
USER_TYPES = {"0x0", "0x1", "0x2", "0x4"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", required=True)
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--seed", type=int, default=303)
    args = ap.parse_args()
    c = args.chain
    out = ROOT / "data" / f"test3_bg_{c}.jsonl"
    have = [json.loads(l) for l in open(out)] if out.exists() else []
    seen = {r["tx_hash"] for r in have}
    need = args.n - len(have)
    rng = random.Random(f"{args.seed}:{c}:{len(have)}")
    lock = threading.Lock()
    exploit_txs = set()
    for f in (ROOT / "data").glob("*exploit*.jsonl"):
        for l in open(f):
            try:
                exploit_txs.update(json.loads(l).get("attack_txs", []))
            except ValueError:
                pass
    al = cm.alchemy(c)
    hi = int(al.rpc("eth_blockNumber", [], cache=False), 16) - 1000
    lo = BLOCK_LO[c]
    es = cm.etherscan(c)

    def candidate(_):
        for _ in range(10):
            with lock:
                b = rng.randrange(lo, hi)
                r2 = random.Random(rng.random())
            try:
                block = al.rpc("eth_getBlockByNumber", [hex(b), True], cache=False)
            except RuntimeError:
                continue
            txs = [t for t in block.get("transactions", [])
                   if t.get("to") and len(t.get("input", "")) > 10 and t.get("type", "0x0") in USER_TYPES
                   and t["hash"].lower() not in exploit_txs]
            r2.shuffle(txs)
            for t in txs[:4]:
                to, h = t["to"].lower(), t["hash"].lower()
                with lock:
                    if h in seen:
                        continue
                try:
                    if not es.source(to)["verified"]:
                        continue
                    rec = cm.replay_and_store(c, h)
                except (RuntimeError, LookupError):
                    continue
                if rec and rec["ok"] and rec["matched"]:
                    with lock:
                        if h in seen:
                            continue
                        seen.add(h)
                    return {"incident": f"test3bg:{c}:{h[:10]}", "chain": c, "source": "background", "tx_hash": h,
                            "label": 0, "block": b, "victim": to, "month": None, "trace_source": rec.get("source")}
        return None

    n_ok = 0
    with ThreadPoolExecutor(args.workers) as pool:
        for row in pool.map(candidate, range(max(need, 0))):
            if row:
                n_ok += 1
                with out.open("a") as fh:
                    fh.write(json.dumps(row) + "\n")
                if n_ok % 20 == 0:
                    print(f"{c}: {len(have) + n_ok} background rows", flush=True)
    cm.close_replayers()
    print(f"done {c}: {len(have) + n_ok} rows -> {out}")


if __name__ == "__main__":
    main()
