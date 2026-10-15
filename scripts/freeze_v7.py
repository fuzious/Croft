"""Freeze the v7 classifier (avg of logreg + hist-gradient-boosting on v7 card features), trained on the whole
dev pool, threshold from out-of-fold predictions at precision >= 0.95. Records code + data hashes.

    uv run python scripts/freeze_v7.py --cards data/cards_v7_hyg.jsonl
"""
import argparse
import hashlib
import json
import pickle
from pathlib import Path

import numpy as np

from eval_baseline import cv_scores, recall_at_precision
from eval_models import Avg

ROOT = Path(__file__).resolve().parents[1]


def code_hash() -> str:
    return hashlib.sha256(b"".join((ROOT / "oracle" / f).read_bytes()
                                   for f in ("card.py", "category.py"))).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", required=True)
    args = ap.parse_args()
    rows = [json.loads(l) for l in open(args.cards)]
    keys = sorted({k for r in rows for k in r["feats"]})
    X = np.array([[float(r["feats"].get(k, 0.0)) for k in keys] for r in rows])
    y = np.array([r["label"] for r in rows])
    g = np.array([r["incident"] for r in rows])
    p = cv_scores(Avg, X, y, g)
    rec, thr, prec = recall_at_precision(y, p, 0.95)
    model = Avg(0).fit(X, y)
    meta = {"model": "avg(logreg C=1, hist_gboost)", "keys": keys, "threshold": thr, "dev_rows": len(rows),
            "dev_exploits": int(y.sum()), "dev_cv_recall": rec, "dev_cv_precision": prec,
            "card_code_sha256": code_hash(),
            "dev_tx_sha256": hashlib.sha256("".join(sorted(r["tx_hash"] for r in rows)).encode()).hexdigest()}
    (ROOT / "models").mkdir(exist_ok=True)
    with open(ROOT / "models" / "frozen_v7.pkl", "wb") as fh:
        pickle.dump({"model": model, **meta}, fh)
    (ROOT / "models" / "frozen_v7.json").write_text(json.dumps(meta, indent=1))
    (ROOT / "models" / "dev_v7_tx_hashes.json").write_text(json.dumps(sorted(r["tx_hash"] for r in rows)))
    print(json.dumps({k: v for k, v in meta.items() if k != "keys"}, indent=1))


if __name__ == "__main__":
    main()
