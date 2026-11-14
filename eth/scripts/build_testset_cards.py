"""Cards for the sealed test set: fresh real-world normals + the held-out rows set aside by freeze_model.py.

The card code must be the frozen one (hash checked against models/frozen_v6.json).

    uv run python scripts/build_testset_cards.py -> data/testset_cards.jsonl
"""
import hashlib
import json
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from oracle.card import CardBuilder
from oracle.category import categorize

ROOT = Path(__file__).resolve().parents[1]


def main():
    meta = json.loads((ROOT / "models" / "frozen_v6.json").read_text())
    code = hashlib.sha256(b"".join((ROOT / "oracle" / f).read_bytes()
                                   for f in ("card.py", "category.py", "sources.py"))).hexdigest()
    assert code == meta["card_code_sha256"], "card code changed since the model was frozen"

    cb = CardBuilder.for_chain("eth")
    normals = [json.loads(l) for l in open(ROOT / "data" / "testset_normals.jsonl")]
    cache = ROOT / "data" / "cards" / "testset"
    cache.mkdir(parents=True, exist_ok=True)

    def one(row):
        path = cache / f"{row['tx_hash']}.json"
        if path.exists():
            return json.loads(path.read_text())
        rp = json.loads((ROOT / "data" / "replays" / f"{row['tx_hash']}.json").read_text())
        try:
            category = categorize(cb.etherscan, row["victim"])
            card, feats, m = cb.build(rp, protected=[row["victim"]], category=category)
        except Exception:  # noqa: BLE001
            print(f"[card error] {row['tx_hash']}\n{traceback.format_exc(limit=2)}", flush=True)
            return None
        out = {**row, "protected": [row["victim"]], "category": category, "card": card, "feats": feats, "meta": m}
        path.write_text(json.dumps(out))
        return out

    with ThreadPoolExecutor(6) as pool:
        cards = [c for c in pool.map(one, normals) if c]
    held = [json.loads(l) for l in open(ROOT / "models" / "holdout_rows.jsonl")]
    rows = cards + held
    (ROOT / "data" / "testset_cards.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"test set: {len(rows)} txs ({sum(r['label'] for r in rows)} exploits, "
          f"{len(rows) - sum(r['label'] for r in rows)} normal)")


if __name__ == "__main__":
    main()
