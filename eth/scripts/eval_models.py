"""Compare classifiers on the dev pool with incident-grouped CV (nested threshold for precision >= target).

    uv run python scripts/eval_models.py --cards data/cards_v7_clean.jsonl
"""
import argparse
import json

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from eval_baseline import cv_scores, report_target, signed_log


def logreg(s, C=1.0):
    return make_pipeline(FunctionTransformer(signed_log), StandardScaler(),
                         LogisticRegression(C=C, max_iter=5000))


def hgb(s):
    return HistGradientBoostingClassifier(max_depth=3, learning_rate=0.06, max_iter=300, l2_regularization=1.0,
                                          min_samples_leaf=10, random_state=s)


def rf(s):
    return RandomForestClassifier(500, min_samples_leaf=2, max_features=0.5, random_state=s, n_jobs=-1)


class Avg:
    """Average of logistic regression and gradient boosting probabilities."""

    def __init__(self, s):
        self.m = [logreg(s), hgb(s)]

    def fit(self, X, y):
        for m in self.m:
            m.fit(X, y)
        return self

    def predict_proba(self, X):
        return np.mean([m.predict_proba(X) for m in self.m], axis=0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", required=True)
    ap.add_argument("--target", type=float, default=0.95)
    args = ap.parse_args()
    rows = [json.loads(l) for l in open(args.cards)]
    keys = sorted({k for r in rows for k in r["feats"]})
    X = np.array([[float(r["feats"].get(k, 0.0)) for k in keys] for r in rows])
    y = np.array([r["label"] for r in rows])
    g = np.array([r["incident"] for r in rows])
    print(f"{len(rows)} rows ({int(y.sum())} exploits, {int((y == 0).sum())} normal), {len(keys)} features")
    out = {}
    for name, fn in {"logreg": logreg, "logreg_C0.3": lambda s: logreg(s, 0.3), "hist_gboost": hgb,
                     "random_forest": rf, "avg(logreg,hgb)": Avg}.items():
        p = cv_scores(fn, X, y, g)
        prec, rec = report_target(name, y, p, g, args.target)
        out[name] = p
    np.save(str(__import__("pathlib").Path(__file__).resolve().parents[1] / "runs" / "eval_models_probs.npy"), np.array([out[k] for k in out]))
    (__import__("pathlib").Path(__file__).resolve().parents[1] / "runs" / "eval_models_keys.json").write_text(json.dumps(list(out)))


if __name__ == "__main__":
    main()
