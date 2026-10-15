"""Data hygiene: a victim normal must predate its attack by >= MIN_GAP blocks (outside the attack window,
where attacker setup txs, multi-tx attacks and copycats live). Uniform rule, applied to every incident.

ETH normals inside the window are re-sampled from before (attack_block - MIN_GAP); BSC ones are dropped
(their block-scan sampler only looked 300 blocks back).

    uv run python scripts/resample_victim_normals.py --cards data/cards_v7_clean.jsonl --version v7
"""
import argparse
import json
from pathlib import Path

import build_dataset as bd
from oracle.card import CardBuilder

ROOT = Path(__file__).resolve().parents[1]
MIN_GAP = 7_200  # ~1 day on Ethereum


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", required=True)
    ap.add_argument("--version", default="v7")
    args = ap.parse_args()
    rows = [json.loads(l) for l in open(args.cards)]
    attack = {r["incident"]: r for r in rows if r["label"] == 1}
    cb = CardBuilder.for_chain("eth")
    out, n_resampled, n_dropped = [], 0, 0
    for r in rows:
        ex = attack.get(r["incident"])
        if r["label"] == 1 or ex is None or ex["block"] - r["block"] >= MIN_GAP:
            out.append(r)
            continue
        if r.get("chain", "eth") != "eth":
            n_dropped += 1
            continue
        bad = {ex["meta"]["signer"]} if ex.get("meta") else set()
        new = None
        for h in bd.pick_normal(r["victim"], ex["block"] - MIN_GAP, bad):
            rec = bd.replay_and_store(h)
            if rec and rec["ok"] and rec["matched"]:
                card, feats, meta = cb.build(rec, protected=r["protected"], category=r["category"])
                new = {**r, "tx_hash": h, "block": int(rec["tx"]["blockNumber"], 16), "card": card,
                       "feats": feats, "meta": meta, "resampled_from": r["tx_hash"]}
                break
        if new:
            out.append(new)
            n_resampled += 1
        else:
            n_dropped += 1
    path = Path(args.cards).with_name(Path(args.cards).stem.replace("_clean", "") + "_hyg.jsonl")
    path.write_text("".join(json.dumps(r) + "\n" for r in out))
    print(f"victim normals re-sampled {n_resampled}, dropped {n_dropped}; {len(out)} rows -> {path}")


if __name__ == "__main__":
    main()
