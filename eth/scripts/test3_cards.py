"""Sealed test v3: card background normals with the unmodified CardBuilder, merge with exploit/victim rows,
apply the harm rule to exploit rows, run integrity checks, write data/test3_cards.jsonl.

    TEST3_ES_RATE=2.5 uv run python scripts/test3_cards.py --workers 4
Per-tx card cache: data/cards/test3/<hash>.json
"""
import argparse
import json
import re
import sys
import traceback
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test3_common as cm  # noqa: E402
from oracle.category import categorize  # noqa: E402
from test3_exploits import builder  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "data" / "cards" / "test3"
KEYS = ("card", "feats", "meta", "label", "chain", "incident", "tx_hash", "victim", "protected", "category", "group")
HASH = re.compile(r"0x[0-9a-f]{64}")


def card_bg(row):
    path = CACHE / f"{row['tx_hash']}.json"
    if path.exists():
        return json.loads(path.read_text())
    c = row["chain"]
    rp = json.loads((ROOT / "data" / "replays" / f"{row['tx_hash']}.json").read_text())
    try:
        protected = [row["victim"]]
        category = categorize(cm.etherscan(c), protected[-1])
        card, feats, meta = builder(c).build(rp, protected=protected, category=category)
    except Exception:  # noqa: BLE001
        print(f"[card error] {row['tx_hash']}\n{traceback.format_exc(limit=2)}", flush=True)
        return None
    out = {**row, "protected": protected, "category": category, "group": row["incident"],
           "card": card, "feats": feats, "meta": meta}
    path.write_text(json.dumps(out))
    return out


def existing_hashes() -> set:
    seen = set()
    files = [p for p in (ROOT / "data").glob("*.jsonl") if not p.name.startswith("test3_")]
    files += sorted((ROOT / "models").glob("*_tx_hashes.json"))
    for f in files:
        with open(f, errors="ignore") as fh:
            for line in fh:
                seen.update(HASH.findall(line.lower()))
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()
    CACHE.mkdir(parents=True, exist_ok=True)
    ex = {}
    for l in open(ROOT / "data" / "test3_exploit_rows.jsonl"):
        r = json.loads(l)
        ex[(r["incident"], r["label"])] = r  # last write wins on reruns
    stats = Counter()
    rows = []
    for r in ex.values():
        if r["label"] == 1:
            stats[f"{r['chain']}:exploit_carded"] += 1
            if not r["harmful"]:
                stats[f"{r['chain']}:exploit_dropped_not_harmful"] += 1
                continue
            stats[f"{r['chain']}:exploit_kept"] += 1
        else:
            stats[f"{r['chain']}:victim_normal"] += 1
        rows.append(r)
    bg = []
    for c in ("polygon", "arbitrum", "optimism"):
        p = ROOT / "data" / f"test3_bg_{c}.jsonl"
        if p.exists():
            bg += [json.loads(l) for l in open(p)]
    with ThreadPoolExecutor(args.workers) as pool:
        carded = list(pool.map(card_bg, bg))
    for r in carded:
        if r:
            stats[f"{r['chain']}:background"] += 1
            rows.append(r)
    stats["background_card_errors"] = sum(1 for r in carded if r is None)

    # ---- integrity ----
    out_rows, seen = [], set()
    old = existing_hashes()
    for r in rows:
        h = r["tx_hash"].lower()
        if h in old:
            stats["dropped_overlap_existing"] += 1
            continue
        if h in seen:
            stats["dropped_duplicate"] += 1
            continue
        seen.add(h)
        out_rows.append({**{k: r.get(k) for k in KEYS},
                         **{k: r[k] for k in ("source", "trace_source", "month", "block", "extractor", "gap_seconds")
                            if k in r}})
    hashes = [r["tx_hash"] for r in out_rows]
    assert len(hashes) == len(set(hashes)), "duplicate tx hashes"
    assert not (set(hashes) & old), "overlap with existing data"
    (ROOT / "data" / "test3_cards.jsonl").write_text("".join(json.dumps(r) + "\n" for r in out_rows))
    n_ex = sum(r["label"] for r in out_rows)
    print(f"{len(out_rows)} rows ({n_ex} exploit / {len(out_rows) - n_ex} normal) -> data/test3_cards.jsonl")
    print(json.dumps(dict(sorted(stats.items())), indent=1))


if __name__ == "__main__":
    main()
