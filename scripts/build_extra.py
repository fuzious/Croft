"""Replay extra rows into data/dataset_extra.jsonl:
  - rekt.news incidents (victim inferred from the replay: the verified contract with the largest net loss),
    each with a normal tx to that victim from before the attack
  - hard negatives (complex benign txs) from data/hard_negatives.jsonl

    uv run python scripts/build_extra.py --workers 3
"""
import argparse
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from build_dataset import UPSTREAMS, pick_normal, replay_and_store
import build_dataset
from oracle.card import CardBuilder
from oracle.sources import Alchemy, Etherscan, Prices

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "dataset_extra.jsonl"
build_dataset.ports = iter(range(8800, 8900))
cb = CardBuilder(Alchemy(), Etherscan(), Prices())
lock = threading.Lock()


def emit(rows):
    with lock, OUT.open("a") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def rekt_incident(inc):
    for h in inc["attack_txs"]:
        try:
            ex = replay_and_store(h)
        except LookupError:
            continue
        if not (ex["ok"] and ex["matched"]):
            continue
        _, _, meta = cb.build(ex)
        victims = [l for l in meta["losers"] if l["kind"] == "verified"]
        if not victims:
            return f"{inc['name']}: no verified victim lost value"
        victim = victims[0]["addr"]
        block = int(ex["tx"]["blockNumber"], 16)
        base = {"incident": inc["name"], "month": inc.get("month"), "victim": victim,
                "victim_name": victims[0]["name"], "source": "rekt"}
        rows = [{**base, "tx_hash": h, "label": 1, "block": block}]
        for n in pick_normal(victim, block, {ex["tx"]["from"].lower()}):
            try:
                nr = replay_and_store(n)
            except Exception:  # noqa: BLE001
                continue
            if nr["ok"] and nr["matched"]:
                rows.append({**base, "tx_hash": n, "label": 0, "block": int(nr["tx"]["blockNumber"], 16)})
                break
        emit(rows)
        return f"{inc['name']}: {len(rows)} rows (victim {victims[0]['name']})"
    return f"{inc['name']}: no attack tx replayed cleanly"


def hard_negative(row):
    r = replay_and_store(row["tx_hash"])
    if not (r["ok"] and r["matched"]):
        return f"{row['incident']}: replay ok={r['ok']} matched={r['matched']}"
    emit([{**row, "month": None, "block": int(r["tx"]["blockNumber"], 16)}])
    return f"{row['incident']}: ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=3)
    args = ap.parse_args()
    OUT.write_text("")
    jobs = [(rekt_incident, json.loads(l)) for l in open(ROOT / "data" / "incidents_rekt.jsonl")]
    jobs += [(hard_negative, json.loads(l)) for l in open(ROOT / "data" / "hard_negatives.jsonl")]
    with ThreadPoolExecutor(args.workers) as pool:
        futs = [pool.submit(fn, x) for fn, x in jobs]
        for f in as_completed(futs):
            try:
                print(f.result(), flush=True)
            except Exception as e:  # noqa: BLE001
                print(f"[err ] {str(e)[:160]}", flush=True)
    rows = [json.loads(l) for l in open(OUT)]
    print(f"done: {sum(r['label'] for r in rows)} exploits, {sum(1 - r['label'] for r in rows)} normal")


if __name__ == "__main__":
    main()
