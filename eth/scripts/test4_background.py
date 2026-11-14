"""Sealed test v4 background normals (label 0): successful txs to *verified* contracts from random blocks
(same recipe as build_background.py / test3_background.py), with the v4 exclusion set.
eth/base: exact dRPC traces; bsc: anvil replay (kept only if ok and matched: status + log count).

    uv run python scripts/test4_background.py --chain bsc --n 200 --workers 4
Writes data/test4_bg_<chain>.jsonl (appends; resumable). Merged into data/test4_normals.jsonl by test4_merge.py.
"""
import argparse
import json
import random
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test4_common as cm  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
BLOCK_LO = {"eth": 11_565_000, "bsc": 3_500_000, "base": 2_000_000}  # ~2021-01 onwards (base: since launch)
USER_TYPES = {"0x0", "0x1", "0x2", "0x4"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", required=True)
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--seed", type=int, default=90210)
    args = ap.parse_args()
    c = args.chain
    out = ROOT / "data" / f"test4_bg_{c}.jsonl"
    have = [json.loads(l) for l in open(out)] if out.exists() else []
    excluded = cm.used_hashes() | cm.preexisting_replays()
    seen = {r["tx_hash"] for r in have}
    need = args.n - len(have)
    rng = random.Random(f"{args.seed}:{c}:{len(have)}")
    lock = threading.Lock()
    al = cm.rpc(c)
    hi = int(al.rpc("eth_blockNumber", [], cache=False), 16) - 1000
    lo = BLOCK_LO[c]
    es = cm.etherscan(c)

    def candidate(_):
        for _ in range(12):
            with lock:
                b = rng.randrange(lo, hi)
                r2 = random.Random(rng.random())
            try:
                block = al.rpc("eth_getBlockByNumber", [hex(b), True], cache=False)
            except RuntimeError:
                continue
            txs = [t for t in block.get("transactions", [])
                   if t.get("to") and len(t.get("input", "")) > 10 and t.get("type", "0x0") in USER_TYPES
                   and t["hash"].lower() not in excluded]
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
                except Exception:  # noqa: BLE001
                    continue
                if rec and rec["ok"] and rec["matched"]:
                    with lock:
                        if h in seen:
                            continue
                        seen.add(h)
                    return {"incident": f"test4:background_{c}:{h[:10]}", "source": f"background_{c}",
                            "family": "background", "tx_hash": h, "label": 0, "chain": c, "block": b,
                            "victim": to, "group": f"test4:background_{c}:{h[:10]}",
                            "trace_source": rec.get("source", "anvil_replay")}
                break  # one tx per random block window
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
