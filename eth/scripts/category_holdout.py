"""Per-category held-out test slices (never trained on).

For every exploit category, reserve the NEWEST ~25% of incident groups (at least MIN_EX exploits where available),
whole victim groups at a time, so the same protocol is never on both sides. Normals of each category are split by a
stable hash of their group (25% held out). Run this BEFORE training a model version; train only on the train file.

    uv run python scripts/category_holdout.py --rows data/pool_v11_rows.jsonl [--rows data/harm_train.jsonl] \
        --tag v12
  -> data/cat_holdout_<tag>.jsonl (sealed, per-category test) + data/cat_train_<tag>.jsonl
"""
import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
    
ROOT = Path(__file__).resolve().parents[1]
FRACTION, MIN_EX = 0.25, 8


def category(r: dict) -> str:
    kind = r.get("kind") or ""
    if kind.startswith("drainer_nft"):
        return "drainer-nft"
    if kind.startswith("drainer"):
        return "drainer-token"
    if kind.endswith("_nft"):
        return "nft"
    if kind.endswith("_vault"):
        return "vault/yield"
    return r.get("category") or "other"


def when(r: dict) -> int:
    p = ROOT / "data" / "replays" / f"{r['tx_hash']}.json"
    try:
        return int(json.loads(p.read_text())["block"]["timestamp"], 16)
    except (OSError, KeyError, ValueError):
        return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", action="append", required=True)
    ap.add_argument("--tag", required=True)
    args = ap.parse_args()
    rows, seen = [], set()
    for f in args.rows:
        for l in open(f):
            r = json.loads(l)
            if r["tx_hash"] not in seen:
                seen.add(r["tx_hash"])
                r.setdefault("group", r["incident"])
                r["cat"] = category(r)
                rows.append(r)

    # one category per group (its exploit's category if it has one), so a group never splits across sides
    by_group = defaultdict(list)
    for r in rows:
        by_group[r["group"]].append(r)
    for g, rs in by_group.items():
        cat = next((x["cat"] for x in rs if x["label"]), rs[0]["cat"])
        for x in rs:
            x["cat"] = cat
    # exploit groups per category, newest first
    groups = defaultdict(lambda: defaultdict(list))
    for r in rows:
        groups[r["cat"]][r["group"]].append(r)
    held_groups = set()
    for cat, gs in groups.items():
        ex_groups = [(g, rs) for g, rs in gs.items() if any(x["label"] for x in rs)]
        n_ex = sum(sum(x["label"] for x in rs) for _, rs in ex_groups)
        target = min(max(round(FRACTION * n_ex), MIN_EX), n_ex // 2)  # never more than half of a category
        ex_groups.sort(key=lambda gr: -max(when(x) for x in gr[1] if x["label"]))
        got = 0
        for g, rs in ex_groups:
            if got >= target:
                break
            held_groups.add((cat, g))
            got += sum(x["label"] for x in rs)

    def held(r):
        if (r["cat"], r["group"]) in held_groups:
            return True
        if any(x["label"] for x in groups[r["cat"]][r["group"]]):
            return False  # training-side exploit group (its victim normals stay with it)
        h = int(hashlib.sha256(f"{r['cat']}|{r['group']}".encode()).hexdigest(), 16) % 100
        return h < FRACTION * 100

    hold = [r for r in rows if held(r)]
    train = [r for r in rows if not held(r)]
    assert not ({r["tx_hash"] for r in hold} & {r["tx_hash"] for r in train})
    assert not ({r["group"] for r in hold} & {r["group"] for r in train}), "a group straddles train/holdout"
    (ROOT / "data" / f"cat_holdout_{args.tag}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in hold))
    (ROOT / "data" / f"cat_train_{args.tag}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in train))
    print(f"{'category':14s} {'train ex':>8s} {'held ex':>8s} {'train norm':>10s} {'held norm':>10s}")
    for cat in sorted(groups):
        c = lambda rs, lab: sum(1 for r in rs if r["cat"] == cat and r["label"] == lab)  # noqa: E731
        print(f"{cat:14s} {c(train, 1):8d} {c(hold, 1):8d} {c(train, 0):10d} {c(hold, 0):10d}")
    print(f"total: train {len(train)} rows, held-out {len(hold)} rows")


if __name__ == "__main__":
    main()
