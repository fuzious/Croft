"""Freeze v9: avg(logreg, hist-gboost) on v9 card features (chain-proxy feature excluded), trained on the whole dev
pool; threshold from grouped out-of-fold predictions at precision >= 0.95.

Fixes from review: the estimator is stored under "estimator" (metadata no longer overwrites it); the code hash covers
card.py + category.py + sources.py; the data hash covers (tx, label, features); the artifact is reloaded and its
predictions verified before it is accepted.

    uv run python scripts/freeze_v9.py --cards data/cards_v9_clean.jsonl
"""
import argparse
import hashlib
import json
import pickle
from pathlib import Path

import numpy as np
from sklearn.model_selection import GroupKFold

from eval_models import Avg, hgb, logreg
from eval_nested import EXCLUDE_FEATS, feature_matrix, group_ids, threshold_for_precision

ROOT = Path(__file__).resolve().parents[1]


def code_hash() -> str:
    return hashlib.sha256(b"".join((ROOT / "oracle" / f).read_bytes()
                                   for f in ("card.py", "category.py", "sources.py"))).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", required=True)
    ap.add_argument("--model", choices=["avg", "logreg", "hgb"], default="avg")
    ap.add_argument("--tag", default="v9")
    args = ap.parse_args()
    make = {"avg": Avg, "logreg": lambda s: logreg(s), "hgb": lambda s: hgb(s)}[args.model]
    rows = [json.loads(l) for l in open(args.cards)]
    assert len({r["tx_hash"] for r in rows}) == len(rows), "duplicate tx in dev"
    keys = sorted({k for r in rows for k in r["feats"]} - EXCLUDE_FEATS)
    X, y, g = feature_matrix(rows, keys), np.array([r["label"] for r in rows]), group_ids(rows)
    assert np.isfinite(X).all(), "non-finite feature values"

    oof = np.zeros(len(y))
    for tr, te in GroupKFold(5).split(X, y, g):
        oof[te] = make(0).fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
    thr = threshold_for_precision(y, oof, 0.95)
    est = make(0).fit(X, y)

    data_blob = json.dumps([[r["tx_hash"], r["label"], [r["feats"].get(k, 0.0) for k in keys]] for r in rows],
                           sort_keys=True).encode()
    rows_set = {r["tx_hash"] for r in rows}
    meta = {"model_name": {"avg": "avg(logreg C=1, hist_gboost)", "logreg": "logreg C=1 (signed-log, standardized)",
                           "hgb": "hist gradient boosting (depth 3, 300 iters)"}[args.model], "feature_keys": keys, "excluded_features": sorted(EXCLUDE_FEATS),
            "threshold": thr, "dev_rows": len(rows), "dev_exploits": int(y.sum()),
            "card_code_sha256": code_hash(), "dev_rows_sha256": hashlib.sha256(data_blob).hexdigest(),
            "label_policy_sha256": hashlib.sha256((ROOT / "data" / "label_policy.json").read_bytes()).hexdigest()}
    path = ROOT / "models" / f"frozen_{args.tag}.pkl"
    with open(path, "wb") as fh:
        pickle.dump({"estimator": est, "meta": meta}, fh)
    reloaded = pickle.loads(path.read_bytes())
    assert np.allclose(reloaded["estimator"].predict_proba(X[:50]), est.predict_proba(X[:50])), "reload mismatch"
    (ROOT / "models" / f"frozen_{args.tag}.json").write_text(json.dumps(meta, indent=1))
    (ROOT / "models" / f"dev_{args.tag}_tx_hashes.json").write_text(json.dumps(sorted(rows_set)))
    print(json.dumps({k: v for k, v in meta.items() if k != "feature_keys"}, indent=1))


if __name__ == "__main__":
    main()
