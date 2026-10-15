"""Non-LLM baseline on card features: incident-grouped cross-validation (an exploit and its normal tx
from the same victim always land in the same fold).

    uv run python scripts/eval_baseline.py --cards data/cards_v1.jsonl
"""
import argparse
import json

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler


def signed_log(x):
    return np.sign(x) * np.log1p(np.abs(x))


def load(path, chain=None):
    rows = [json.loads(l) for l in open(path)]
    if chain:
        rows = [r for r in rows if r.get("chain", "eth") == chain]
    keys = sorted(rows[0]["feats"])
    X = np.array([[float(r["feats"].get(k, 0.0)) for k in keys] for r in rows])
    y = np.array([r["label"] for r in rows])
    groups = np.array([r["incident"] for r in rows])
    return rows, keys, X, y, groups


def cv_scores(model_fn, X, y, groups, folds=5, seeds=(0, 1, 2)):
    probs = np.zeros((len(seeds), len(y)))
    for si, seed in enumerate(seeds):
        rng = np.random.RandomState(seed)
        uniq = np.unique(groups)
        perm = {g: i for i, g in enumerate(rng.permutation(uniq))}
        g = np.array([perm[x] for x in groups])
        for tr, te in GroupKFold(folds).split(X, y, g):
            m = model_fn(seed)
            m.fit(X[tr], y[tr])
            probs[si, te] = m.predict_proba(X[te])[:, 1]
    return probs.mean(0)


def recall_at_precision(y, p, target=0.95):
    """Max recall over thresholds with precision >= target (on these predictions)."""
    best = (0.0, 1.0, 0.0)
    for t in np.unique(p):
        pred = p >= t
        tp = int((pred & (y == 1)).sum())
        if not pred.sum():
            continue
        prec, rec = tp / pred.sum(), tp / max(1, (y == 1).sum())
        if prec >= target and rec > best[0]:
            best = (rec, float(t), prec)
    return best


def report_target(name, y, p, groups, target=0.95, folds=5):
    """Honest operating point: threshold picked on the other folds' predictions, applied to the held-out fold."""
    pred = np.zeros(len(y), dtype=int)
    uniq = np.unique(groups)
    perm = {g: i for i, g in enumerate(np.random.RandomState(0).permutation(uniq))}
    g = np.array([perm[x] for x in groups])
    for tr, te in GroupKFold(folds).split(p, y, g):
        _, thr, _ = recall_at_precision(y[tr], p[tr], target)
        pred[te] = (p[te] >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    best_rec, best_thr, _ = recall_at_precision(y, p, target)
    print(f"{name:28s} @P>={target:.2f} (nested thr): P={prec:.3f} R={rec:.3f} FP={fp} FN={fn} | "
          f"oracle-thr R={best_rec:.3f} thr={best_thr:.3f}", flush=True)
    return prec, rec


def report(name, y, p, thr=0.5):
    pred = (p >= thr).astype(int)
    print(f"{name:28s} P={precision_score(y, pred, zero_division=0):.3f} R={recall_score(y, pred):.3f} "
          f"F1={f1_score(y, pred):.3f} AUC={roc_auc_score(y, p):.3f}  (n={len(y)}, thr={thr})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", default="data/cards_v1.jsonl")
    ap.add_argument("--chain", default=None)
    args = ap.parse_args()
    rows, keys, X, y, groups = load(args.cards, args.chain)
    print(f"{len(y)} rows, {y.sum()} exploits, {len(np.unique(groups))} incidents, {len(keys)} features")
    models = {
        "logreg": lambda s: make_pipeline(FunctionTransformer(signed_log), StandardScaler(),
                                          LogisticRegression(C=1.0, max_iter=2000)),
        "random_forest": lambda s: RandomForestClassifier(300, min_samples_leaf=2, random_state=s),
        "gboost": lambda s: GradientBoostingClassifier(random_state=s, max_depth=2, n_estimators=150),
    }
    for name, fn in models.items():
        p = cv_scores(fn, X, y, groups)
        report(name, y, p)
        report_target(name, y, p, groups)
    rf = RandomForestClassifier(500, min_samples_leaf=2, random_state=0).fit(X, y)
    top = sorted(zip(rf.feature_importances_, keys), reverse=True)[:10]
    print("RF importances:", ", ".join(f"{k}={v:.2f}" for v, k in top))


if __name__ == "__main__":
    main()
