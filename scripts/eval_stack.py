"""Stack Laya's out-of-fold P(exploit) with the numeric card features in a logistic meta-model.

Laya's predictions are already out-of-fold (eval_laya.py --mode finetune), so a second grouped CV over
[features + logit(p_laya)] is ordinary stacking. Also reports per-category precision/recall.

    uv run python scripts/eval_stack.py --cards data/cards_v4.jsonl --laya runs/<tag>/predictions.jsonl
"""
import argparse
import json
from collections import defaultdict

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from eval_baseline import cv_scores, report, report_target, signed_log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", required=True)
    ap.add_argument("--laya", default=None)
    ap.add_argument("--thr", type=float, default=0.5)
    ap.add_argument("--chain", default=None)
    args = ap.parse_args()
    rows = [json.loads(l) for l in open(args.cards)]
    if args.chain:
        rows = [r for r in rows if r.get("chain", "eth") == args.chain]
    keys = sorted(rows[0]["feats"])
    X = np.array([[float(r["feats"].get(k, 0.0)) for k in keys] for r in rows])
    y = np.array([r["label"] for r in rows])
    groups = np.array([r["incident"] for r in rows])

    def logreg(_seed):
        return make_pipeline(FunctionTransformer(signed_log), StandardScaler(), LogisticRegression(C=0.5, max_iter=3000))

    p_feat = cv_scores(logreg, X, y, groups)
    report("features (logreg)", y, p_feat, args.thr)
    report_target("features (logreg)", y, p_feat, groups)
    final = p_feat
    if args.laya:
        lp = {json.loads(l)["tx_hash"]: json.loads(l)["p_exploit"] for l in open(args.laya)}
        p_laya = np.array([lp[r["tx_hash"]] for r in rows])
        report("laya alone", y, p_laya, args.thr)
        z = np.log(np.clip(p_laya, 1e-4, 1 - 1e-4) / (1 - np.clip(p_laya, 1e-4, 1 - 1e-4)))
        Xs = np.hstack([X, z[:, None]])
        final = cv_scores(logreg, Xs, y, groups)
        report("stack (features + laya)", y, final, args.thr)
        report_target("laya alone", y, p_laya, groups)
        report_target("stack (features + laya)", y, final, groups)

    by_cat = defaultdict(list)
    for i, r in enumerate(rows):
        by_cat[r.get("category", "unknown")].append(i)
    print("per category (final model):")
    for cat, idx in sorted(by_cat.items(), key=lambda kv: -len(kv[1])):
        yy, pp = y[idx], (final[idx] >= args.thr).astype(int)
        tp, fp, fn = int(((pp == 1) & (yy == 1)).sum()), int(((pp == 1) & (yy == 0)).sum()), int(((pp == 0) & (yy == 1)).sum())
        prec = tp / (tp + fp) if tp + fp else float("nan")
        rec = tp / (tp + fn) if tp + fn else float("nan")
        print(f"  {cat:12s} n={len(idx):3d} exploits={int(yy.sum()):3d}  P={prec:.2f} R={rec:.2f}  FP={fp} FN={fn}")
    errs = [(final[i], r) for i, r in enumerate(rows) if (final[i] >= args.thr) != bool(r["label"])]
    print(f"errors ({len(errs)}):")
    for p, r in sorted(errs, key=lambda e: -abs(e[0] - 0.5))[:12]:
        print(f"  {'FP' if not r['label'] else 'FN'} p={p:.2f} {r['incident']} {r['tx_hash'][:12]} {r.get('category')}")


if __name__ == "__main__":
    main()
