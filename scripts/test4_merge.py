"""Assemble sealed test v4 normals and validate both v4 files (hash membership only; no card/feature contents).

    uv run python scripts/test4_merge.py
Reads data/test4_eth_families.jsonl + data/test4_bg_{eth,bsc,base}.jsonl -> data/test4_normals.jsonl.
Asserts: unique tx hashes within and across data/test4_normals.jsonl / data/test4_exploits.jsonl; no hash used
anywhere else in the project; data/replays/<hash>.json exists with ok and matched for every row.
"""
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test4_common as cm  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
PARTS = ["test4_eth_families.jsonl", "test4_bg_eth.jsonl", "test4_bg_bsc.jsonl", "test4_bg_base.jsonl"]
KEYS = ["incident", "source", "family", "tx_hash", "label", "chain", "block", "victim", "group", "trace_source"]


def replay_ok(h: str) -> bool:
    p = cm.REPLAYS / f"{h}.json"
    if not p.exists():
        return False
    r = json.loads(p.read_text())
    return bool(r.get("ok") and r.get("matched") and r.get("trace"))


def main():
    used = cm.used_hashes()
    rows, dropped = [], Counter()
    seen = set()
    for part in PARTS:
        f = DATA / part
        if not f.exists():
            continue
        for l in open(f):
            r = json.loads(l)
            h = r["tx_hash"].lower()
            if h in used:
                dropped["used elsewhere"] += 1
                continue
            if h in seen:
                dropped["duplicate"] += 1
                continue
            if not replay_ok(h):
                dropped["replay missing/not ok"] += 1
                continue
            seen.add(h)
            rows.append({k: r.get(k) for k in KEYS})
    ex = [json.loads(l) for l in open(DATA / "test4_exploits.jsonl")] if (DATA / "test4_exploits.jsonl").exists() else []
    ex_hashes = [r["tx_hash"] for r in ex]
    assert len(ex_hashes) == len(set(ex_hashes)), "duplicate exploit tx"
    assert not (set(ex_hashes) & seen), "exploit tx also sampled as normal"
    assert not (set(ex_hashes) & used), "exploit tx used elsewhere"
    assert all(replay_ok(h) for h in ex_hashes), "exploit replay missing"
    cand = [h for r in ex for h in r["attack_candidates"]]
    assert not (set(cand) & seen), "attack candidate sampled as normal"
    assert len(rows) == len({r["tx_hash"] for r in rows})
    # victim-address membership in earlier incident lists (address string only; no contents inspected)
    lists = [p for p in DATA.glob("*.jsonl") if not p.name.startswith("test4_")
             and ("exploit" in p.name or "rekt" in p.name or "incident" in p.name)]
    lists_txt = "\n".join(p.read_text(errors="ignore").lower() for p in lists)
    any_txt = "\n".join(p.read_text(errors="ignore").lower() for p in DATA.glob("*.jsonl")
                         if not p.name.startswith("test4_"))
    for r in ex:
        r["victim_in_prior_incident_lists"] = r["victim"] in lists_txt
        r["victim_in_any_prior_data"] = r["victim"] in any_txt
    (DATA / "test4_exploits.jsonl").write_text("".join(json.dumps(r) + "\n" for r in ex))
    print("exploit victims already in prior incident lists:", sum(r["victim_in_prior_incident_lists"] for r in ex),
          "/ in any prior data file:", sum(r["victim_in_any_prior_data"] for r in ex))
    (DATA / "test4_normals.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"normals: {len(rows)} rows (dropped {dict(dropped)})")
    print("by chain:", dict(Counter(r["chain"] for r in rows)))
    print("by family:", dict(Counter(r["family"] for r in rows)))
    print("by source:", dict(sorted(Counter(r["source"] for r in rows).items())))
    yrs = Counter()
    for r in rows:
        if r["chain"] == "eth":
            b = r["block"]
            yrs["2021" if b < 13_916_000 else "2022" if b < 16_308_000 else "2023" if b < 18_908_000 else
                "2024" if b < 21_525_000 else "2025" if b < 24_136_000 else "2026"] += 1
    print("eth by year (approx):", dict(sorted(yrs.items())))
    print(f"exploits: {len(ex)} rows by chain {dict(Counter(r['chain'] for r in ex))}")


if __name__ == "__main__":
    main()
