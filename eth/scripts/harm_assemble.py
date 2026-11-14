"""Merge harm_* collections into data/harm_rows.jsonl and split by time into harm_train / harm_test.

Checks: unique tx hashes, none present in the exclusion set (data/*.jsonl except harm_*, models/*_tx_hashes.json),
and data/replays/<hash>.json exists with ok and matched.
Split: month >= 2025-07 -> test. Label-1 groups (drainer clusters, incidents) are kept intact: the whole group
goes to the split of its first-seen month. Normals (groups = sources spanning years) split per row.

    uv run python scripts/harm_assemble.py
"""
import json
from collections import Counter, defaultdict

import harm_common as hc

PARTS = ["harm_drainers.jsonl", "harm_exploits.jsonl", "harm_normals.jsonl"]
CUT = "2025-07"


def main():
    used = hc.used_hashes()
    rows, seen, drop = [], set(), Counter()
    for name in PARTS:
        p = hc.DATA / name
        for l in (open(p) if p.exists() else []):
            r = json.loads(l)
            h = r["tx_hash"]
            if h in seen:
                drop["duplicate"] += 1
                continue
            if h in used:
                drop["already_used"] += 1
                continue
            rp = hc.REPLAYS / f"{h}.json"
            if not rp.exists():
                drop["no_replay"] += 1
                continue
            rec = json.loads(rp.read_text())
            if not (rec.get("ok") and rec.get("matched")):
                drop["replay_not_ok"] += 1
                continue
            seen.add(h)
            rows.append(r)
    rows.sort(key=lambda r: (r["kind"], r["block"]))
    (hc.DATA / "harm_rows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))

    first = defaultdict(lambda: "9999")
    for r in rows:
        if r["label"] == 1:
            first[r["group"]] = min(first[r["group"]], r["month"])
    train, test, moved = [], [], Counter()
    for r in rows:
        m = first[r["group"]] if r["label"] == 1 else r["month"]
        (test if m >= CUT else train).append(r)
        if (m >= CUT) != (r["month"] >= CUT):
            moved[r["kind"]] += 1
    (hc.DATA / "harm_train.jsonl").write_text("".join(json.dumps(r) + "\n" for r in train))
    (hc.DATA / "harm_test.jsonl").write_text("".join(json.dumps(r) + "\n" for r in test))

    print("dropped:", dict(drop))
    print("rows:", len(rows), dict(Counter(r["kind"] for r in rows)))
    print("train:", len(train), dict(Counter(r["kind"] for r in train)))
    print("test:", len(test), dict(Counter(r["kind"] for r in test)))
    print("rows placed by group first-seen instead of own month:", dict(moved))
    print("label-1 groups train/test:", len({r["group"] for r in train if r["label"]}),
          len({r["group"] for r in test if r["label"]}))
    print("by year:", dict(sorted(Counter((r["kind"], r["month"][:4]) for r in rows).items())))


if __name__ == "__main__":
    main()
