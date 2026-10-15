"""Assemble sealed test v2 rows: nothing here may appear in the v7 dev pool (or anything trained/inspected before).

  normals : data/test2_normals.jsonl (fresh real-world ETH traffic, seed 777, incl. 2025-2026 blocks)
  exploits: Base incidents (chain never seen) + BSC incidents collected after the v6 freeze
  (Base/BSC victim normals come from a 300-block pre-attack scan, i.e. inside the attack window -> excluded by
   the same hygiene rule as the dev pool.)

    uv run python scripts/assemble_test2.py -> data/test2_rows.jsonl
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    dev = set(json.loads((ROOT / "models" / "dev_v7_tx_hashes.json").read_text()))
    seen = set(dev)
    for f in ("cards_v6.jsonl", "cards_v7.jsonl", "testset_cards.jsonl"):
        seen.update(json.loads(l)["tx_hash"] for l in open(ROOT / "data" / f))
    seen_incidents = {json.loads(l)["incident"] for f in ("cards_v6.jsonl", "cards_v7.jsonl")
                      for l in open(ROOT / "data" / f)}
    rows = []
    for l in open(ROOT / "data" / "test2_normals.jsonl"):
        r = json.loads(l)
        if r["tx_hash"] not in seen:
            rows.append(r)
    for f in ("test2_base.jsonl", "dataset_bsc.jsonl"):
        for l in open(ROOT / "data" / f):
            r = json.loads(l)
            if r["label"] == 1 and r["tx_hash"] not in seen and r["incident"] not in seen_incidents:
                rows.append(r)
    (ROOT / "data" / "test2_rows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    ex = [r for r in rows if r["label"]]
    print(f"test v2 rows: {len(rows)} ({len(ex)} exploits: "
          f"{sum(1 for r in ex if r['chain'] == 'base')} base, {sum(1 for r in ex if r['chain'] == 'bsc')} bsc; "
          f"{len(rows) - len(ex)} normals)")


if __name__ == "__main__":
    main()
