"""Random background traffic (label 0): successful txs to *verified* contracts from random blocks.

Estimates precision on the realistic mix a guard sees, and gives each chain its own negatives so the
model cannot learn "this chain => exploit".

    uv run python scripts/build_background.py --chain eth --n 120
    uv run python scripts/build_background.py --chain bsc --n 120 --workers 2
"""
import argparse
import json
import random
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import build_dataset as bd

ROOT = Path(__file__).resolve().parents[1]
BLOCK_RANGE = {"eth": (11_600_000, 23_500_000), "bsc": (5_000_000, 127_000_000), "base": (2_000_000, 36_000_000)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", default="eth")
    ap.add_argument("--n", type=int, default=120)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--out", default=None, help="output file under data/ (default dataset_bg_<chain>.jsonl)")
    args = ap.parse_args()
    bd.configure(args.chain)
    if args.chain == "bsc":
        bd.PORT_BASE = 9200
        bd.ports = iter(range(9200, 9300))
    rng = random.Random(args.seed)
    exploit_txs = set()
    for f in ("exploits_all.jsonl", "exploits_bsc.jsonl"):
        if (ROOT / "data" / f).exists():
            for l in open(ROOT / "data" / f):
                exploit_txs.update(json.loads(l)["attack_txs"])
    lo, hi = BLOCK_RANGE[args.chain]
    head = int(bd.alchemy.rpc("eth_blockNumber", [], cache=False), 16)
    hi = min(hi, head - 1000)
    out_path = ROOT / "data" / (args.out or f"dataset_bg_{args.chain}.jsonl")
    out_path.write_text("")

    def candidate(_):
        for _ in range(8):
            b = rng.randrange(lo, hi)
            block = bd.alchemy.rpc("eth_getBlockByNumber", [hex(b), True], cache=False)
            txs = [t for t in block.get("transactions", [])
                   if t.get("to") and len(t.get("input", "")) > 10 and t["hash"].lower() not in exploit_txs]
            rng.shuffle(txs)
            for t in txs[:6]:
                to = t["to"].lower()
                h = t["hash"].lower()
                try:
                    if not bd.etherscan.source(to)["verified"]:
                        continue
                    rec = bd.replay_and_store(h)
                except (RuntimeError, LookupError):
                    continue
                if rec and rec["ok"] and rec["matched"]:
                    return {"incident": f"{'test2bg' if args.out else 'bg'}:{args.chain}:{h[:10]}", "chain": args.chain, "source": "background",
                            "tx_hash": h, "label": 0, "block": b, "victim": to, "month": None}
        return None

    n_ok = 0
    with ThreadPoolExecutor(args.workers) as pool:
        for row in pool.map(candidate, range(args.n)):
            if row:
                n_ok += 1
                with out_path.open("a") as fh:
                    fh.write(json.dumps(row) + "\n")
                if n_ok % 20 == 0:
                    print(f"{n_ok} background rows", flush=True)
    print(f"done: {n_ok} background txs -> {out_path}")


if __name__ == "__main__":
    main()
