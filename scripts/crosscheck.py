"""Skeptical cross-check of the feature classifier.

  1. exact recall counts (and the missed exploits by name)
  2. recall when the harm filter is undone (dropped "exploits" put back)
  3. false-positive rate per negative type (victim normals / hard negatives / random background)
  4. ablations: value-flow features only vs structural features only
  5. out-of-time: train on incidents before 2025, test on 2025-2026
  6. what precision would be at realistic base rates

    uv run python scripts/crosscheck.py --cards data/cards_v5.jsonl --clean data/cards_v5_clean.jsonl
"""
import argparse
import json

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from eval_baseline import cv_scores, recall_at_precision, signed_log

VALUE = {"signer_usd", "max_loss_usd", "max_drain_share", "prot_net_usd", "prot_drain_share", "eoa_loss_usd",
         "prot_outflow_to_signer", "n_minted_to_signer", "n_supply_shock", "n_unpriced_gains"}


def model(_s):
    return make_pipeline(FunctionTransformer(signed_log), StandardScaler(), LogisticRegression(C=1.0, max_iter=3000))


def matrix(rows, keys):
    return np.array([[float(r["feats"].get(k, 0.0)) for k in keys] for r in rows])


def neg_type(r):
    i = r["incident"]
    if i.startswith("bg:"):
        return "random background"
    if i.startswith("hardneg:"):
        return "hard neg: " + r.get("source", "?")
    return "victim normal"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", required=True, help="all cards (before harm filter)")
    ap.add_argument("--clean", required=True, help="cards after verify_labels")
    ap.add_argument("--chain", default="eth")
    args = ap.parse_args()
    clean = [r for r in map(json.loads, open(args.clean)) if r.get("chain", "eth") == args.chain]
    allr = [r for r in map(json.loads, open(args.cards)) if r.get("chain", "eth") == args.chain]
    keys = sorted({k for r in clean for k in r["feats"]})
    y = np.array([r["label"] for r in clean])
    g = np.array([r["incident"] for r in clean])
    p = cv_scores(model, matrix(clean, keys), y, g)
    _, thr, _ = recall_at_precision(y, p, 0.95)

    # 1. exact counts
    caught = [(r, pi) for r, pi in zip(clean, p) if r["label"] and pi >= thr]
    missed = [(r, pi) for r, pi in zip(clean, p) if r["label"] and pi < thr]
    fps = [(r, pi) for r, pi in zip(clean, p) if not r["label"] and pi >= thr]
    print(f"[1] exploits caught {len(caught)}/{len(caught) + len(missed)} = {len(caught) / (len(caught) + len(missed)):.1%}"
          f"  | false alarms {len(fps)}/{int((y == 0).sum())} normals  (thr {thr:.2f})")
    for r, pi in missed:
        print(f"      missed: {r['incident']} p={pi:.2f}")

    # 2. undo the harm filter: score the dropped rows with models trained on clean data (out-of-fold not needed:
    #    dropped rows were never in training)
    dropped = [r for r in allr if r["label"] == 1 and r["tx_hash"] not in {c["tx_hash"] for c in clean}
               and r["incident"] not in {c["incident"] for c in clean if c["label"] == 1}]
    if dropped:
        m = model(0).fit(matrix(clean, keys), y)
        pd = m.predict_proba(matrix(dropped, keys))[:, 1]
        hit = int((pd >= thr).sum())
        tot = len(caught) + len(missed) + len(dropped)
        print(f"[2] dropped low-harm 'exploits': caught {hit}/{len(dropped)}; recall over ALL listed exploits "
              f"{(len(caught) + hit) / tot:.1%} ({len(caught) + hit}/{tot})")

    # 3. FPR per negative type
    print("[3] false-positive rate by negative type:")
    for t in sorted({neg_type(r) for r in clean if not r["label"]}):
        idx = [i for i, r in enumerate(clean) if not r["label"] and neg_type(r) == t]
        fp = int((p[idx] >= thr).sum())
        print(f"      {t:36s} {fp}/{len(idx)} = {fp / len(idx):.1%}")

    # 4. ablations
    for name, ks in (("value-flow only", [k for k in keys if k in VALUE]),
                     ("structure only (no value flow)", [k for k in keys if k not in VALUE])):
        pa = cv_scores(model, matrix(clean, ks), y, g)
        r95, t95, _ = recall_at_precision(y, pa, 0.95)
        print(f"[4] {name:32s} recall@P>=0.95 = {r95:.1%}")

    # 5. out-of-time: exploits + their victim normals by incident month; other negatives by block
    def is_new(r):
        if r.get("month"):
            return r["month"] >= "2025-01"
        return r.get("block", 0) >= 21_525_000  # ~2025-01-01 on Ethereum
    tr = [i for i, r in enumerate(clean) if not is_new(r)]
    te = [i for i, r in enumerate(clean) if is_new(r)]
    X = matrix(clean, keys)
    m = model(0).fit(X[tr], y[tr])
    ptr = cv_scores(model, X[tr], y[tr], g[tr])
    _, thr_old, _ = recall_at_precision(y[tr], ptr, 0.95)
    pte = m.predict_proba(X[te])[:, 1]
    yt = y[te]
    tp = int(((pte >= thr_old) & (yt == 1)).sum()); fp = int(((pte >= thr_old) & (yt == 0)).sum())
    print(f"[5] out-of-time (train <2025: {len(tr)} rows, test 2025-26: {len(te)} rows, {int(yt.sum())} exploits): "
          f"caught {tp}/{int(yt.sum())} = {tp / max(1, yt.sum()):.1%}, false alarms {fp}/{int((yt == 0).sum())}, "
          f"precision {tp / max(1, tp + fp):.1%}")

    # 6. realistic base rates
    rec = len(caught) / (len(caught) + len(missed))
    bg = [i for i, r in enumerate(clean) if neg_type(r) == "random background"]
    fpr_bg = max(int((p[bg] >= thr).sum()), 0.5) / len(bg)  # 0.5 = continuity correction when 0 FPs
    print(f"[6] precision at realistic base rates (recall {rec:.1%}, background FPR <= {fpr_bg:.2%}):")
    for prev in (1e-2, 1e-3, 1e-4, 1e-5):
        prec = rec * prev / (rec * prev + fpr_bg * (1 - prev))
        print(f"      1 exploit per {int(1 / prev):>7,} txs -> precision {prec:.1%}")


if __name__ == "__main__":
    main()
