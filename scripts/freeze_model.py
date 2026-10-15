"""Freeze the classifier before the sealed test: train on the non-holdout data only, pick the threshold by
training-only CV (precision >= 0.95), and record hashes of the code + training rows.

Holdout (never trained on): Ethereum incidents from 2025-06 onward (exploit + its victim normal) and every
BSC row. Their tx hashes are written to models/holdout_exploits.json for the test-set builder.

    uv run python scripts/freeze_model.py --cards data/cards_v6_clean.jsonl
"""
import argparse
import hashlib
import json
import pickle
from pathlib import Path

import numpy as np

from crosscheck import model
from eval_baseline import cv_scores, recall_at_precision

ROOT = Path(__file__).resolve().parents[1]
HOLDOUT_FROM = "2025-06"


def is_holdout(r: dict) -> bool:
    if r.get("chain", "eth") != "eth":
        return True
    return bool(r.get("month")) and r["month"] >= HOLDOUT_FROM and not r["incident"].startswith(("bg:", "hardneg:"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", required=True)
    args = ap.parse_args()
    rows = [json.loads(l) for l in open(args.cards)]
    train = [r for r in rows if not is_holdout(r)]
    hold = [r for r in rows if is_holdout(r)]
    keys = sorted({k for r in train for k in r["feats"]})
    X = np.array([[float(r["feats"].get(k, 0.0)) for k in keys] for r in train])
    y = np.array([r["label"] for r in train])
    g = np.array([r["incident"] for r in train])

    p = cv_scores(model, X, y, g)
    rec, thr, prec = recall_at_precision(y, p, 0.95)
    m = model(0).fit(X, y)

    code_hash = hashlib.sha256(b"".join((ROOT / "oracle" / f).read_bytes()
                                        for f in ("card.py", "category.py", "sources.py"))).hexdigest()
    data_hash = hashlib.sha256("".join(sorted(r["tx_hash"] for r in train)).encode()).hexdigest()
    out = ROOT / "models"
    out.mkdir(exist_ok=True)
    meta = {"keys": keys, "threshold": thr, "train_rows": len(train), "train_exploits": int(y.sum()),
            "train_cv_recall_at_p95": rec, "train_cv_precision": prec, "card_code_sha256": code_hash,
            "train_tx_sha256": data_hash, "holdout_rule": f"eth month >= {HOLDOUT_FROM} or chain != eth"}
    with open(out / "frozen_v6.pkl", "wb") as fh:
        pickle.dump({"model": m, **meta}, fh)
    (out / "frozen_v6.json").write_text(json.dumps(meta, indent=1))
    (out / "holdout_rows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in hold))
    (out / "train_tx_hashes.json").write_text(json.dumps(sorted(r["tx_hash"] for r in train)))
    print(json.dumps({k: v for k, v in meta.items() if k != "keys"}, indent=1))
    print(f"holdout rows set aside: {len(hold)} ({sum(r['label'] for r in hold)} exploits)")


if __name__ == "__main__":
    main()
