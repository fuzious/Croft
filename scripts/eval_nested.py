"""Genuinely nested, group-aware evaluation (fixes the optimism flagged in review).

Outer GroupKFold over CV groups (victim-level). Inside each outer-train split: inner GroupKFold out-of-fold
predictions -> threshold for precision >= target (or "no feasible threshold" = no alerts). Then fit on the whole
outer-train split, score the outer-test fold once, apply that threshold. Decisions are pooled across outer folds.

    uv run python scripts/eval_nested.py --cards data/cards_v9_clean.jsonl
"""
import argparse
import json
import math

import numpy as np
from sklearn.model_selection import GroupKFold

from eval_models import Avg, hgb, logreg

EXCLUDE_FEATS = {"signer_prior_txs_to_prot"}  # -1 on chains without explorer history: a chain proxy


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def threshold_for_precision(y, p, target):
    """Lowest threshold whose precision >= target (max recall). Returns inf when infeasible."""
    best_t, best_r = math.inf, -1.0
    for t in np.unique(p):
        pred = p >= t
        if not pred.any():
            continue
        tp = int((pred & (y == 1)).sum())
        prec, rec = tp / pred.sum(), tp / max(1, int((y == 1).sum()))
        if prec >= target and rec > best_r:
            best_t, best_r = float(t), rec
    return best_t


def feature_matrix(rows, keys):
    return np.array([[float(r["feats"].get(k, 0.0)) for k in keys] for r in rows])


def group_ids(rows):
    names = [r.get("group") or r["incident"] for r in rows]
    uniq = {g: i for i, g in enumerate(sorted(set(names)))}
    return np.array([uniq[g] for g in names])


def nested(model_fn, X, y, g, target=0.95, outer=5, inner=4, seed=0):
    rng = np.random.RandomState(seed)
    perm = rng.permutation(g.max() + 1)
    gp = perm[g]
    decision = np.zeros(len(y), dtype=bool)
    infeasible = 0
    for tr, te in GroupKFold(outer).split(X, y, gp):
        inner_p = np.zeros(len(tr))
        for itr, ite in GroupKFold(inner).split(X[tr], y[tr], gp[tr]):
            m = model_fn(seed).fit(X[tr][itr], y[tr][itr])
            inner_p[ite] = m.predict_proba(X[tr][ite])[:, 1]
        thr = threshold_for_precision(y[tr], inner_p, target)
        infeasible += int(math.isinf(thr))
        m = model_fn(seed).fit(X[tr], y[tr])
        decision[te] = m.predict_proba(X[te])[:, 1] >= thr
    return decision, infeasible


def summarize(name, y, d, infeasible=0):
    tp = int((d & (y == 1)).sum()); fp = int((d & (y == 0)).sum())
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    rl, rh = wilson(tp, pos); fl, fh = wilson(fp, neg)
    prec = tp / max(1, tp + fp)
    print(f"{name:22s} recall {tp}/{pos}={tp / pos:.1%} [{rl:.1%},{rh:.1%}]  FPR {fp}/{neg}={fp / neg:.2%} "
          f"[{fl:.2%},{fh:.2%}]  precision@mix {prec:.1%}  (infeasible outer thr: {infeasible})", flush=True)
    return tp / pos, fp / neg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", required=True)
    ap.add_argument("--target", type=float, default=0.95)
    args = ap.parse_args()
    rows = [json.loads(l) for l in open(args.cards)]
    keys = sorted({k for r in rows for k in r["feats"]} - EXCLUDE_FEATS)
    X, y, g = feature_matrix(rows, keys), np.array([r["label"] for r in rows]), group_ids(rows)
    print(f"{len(rows)} rows, {int(y.sum())} exploits, {g.max() + 1} groups, {len(keys)} features "
          f"(excluded: {sorted(EXCLUDE_FEATS)}); target precision {args.target}")
    for name, fn in {"logreg": logreg, "hist_gboost": hgb, "avg(logreg,hgb)": Avg}.items():
        decs = []
        for seed in (0, 1, 2):
            d, inf = nested(fn, X, y, g, args.target, seed=seed)
            decs.append(d)
        # report seed 0 exactly, plus the spread of recall/FPR over seeds
        summarize(name, y, decs[0], inf)
        recs = [(d & (y == 1)).sum() / (y == 1).sum() for d in decs]
        fprs = [(d & (y == 0)).sum() / (y == 0).sum() for d in decs]
        print(f"{'':22s} over 3 seeds: recall {min(recs):.1%}-{max(recs):.1%}, FPR {min(fprs):.2%}-{max(fprs):.2%}")


if __name__ == "__main__":
    main()
