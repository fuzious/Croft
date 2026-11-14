"""Score sealed test v2 ONCE with frozen v9, stratified (per review): recall per chain on exploits, FPR per chain and
per source on normals, Wilson 95% CIs, false alerts per million, precision as a function of prevalence.
A single pooled precision over this chain-mixed set is printed only as a footnote (it is not a deployment number).

    uv run python scripts/eval_test2.py --cards data/cards_test2v9.jsonl
"""
import argparse
import json
import pickle
from collections import defaultdict
from pathlib import Path

import numpy as np

from eval_nested import wilson
from freeze_v9 import code_hash

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", required=True)
    ap.add_argument("--tag", default="v9")
    ap.add_argument("--name", default="test2", help="which sealed test (names the report files)")
    args = ap.parse_args()
    art = pickle.loads((ROOT / "models" / f"frozen_{args.tag}.pkl").read_bytes())
    est, meta = art["estimator"], art["meta"]
    assert code_hash() == meta["card_code_sha256"], "card code changed since freeze"
    rows = [json.loads(l) for l in open(args.cards)]
    dev = set(json.loads((ROOT / "models" / f"dev_{args.tag}_tx_hashes.json").read_text()))
    assert set(meta["feature_keys"]) <= set(rows[0]["feats"]), "test cards lack frozen feature keys (schema)"
    assert all(set(r["feats"]) == set(rows[0]["feats"]) for r in rows), "inconsistent feature schema in test"
    assert len({r["tx_hash"] for r in rows}) == len(rows), "duplicate tx in test"
    assert not dev & {r["tx_hash"] for r in rows}, "test overlaps dev"
    X = np.array([[float(r["feats"].get(k, 0.0)) for k in meta["feature_keys"]] for r in rows])
    assert np.isfinite(X).all()
    p = est.predict_proba(X)[:, 1]
    flag = p >= meta["threshold"]
    y = np.array([r["label"] for r in rows])

    out = [f"SEALED {args.name.upper()} (frozen {args.tag}, threshold {meta['threshold']:.3f}), {len(rows)} txs"]
    out.append("Exploits caught (recall), by chain:")
    for ch in sorted({r.get("chain", "eth") for r in rows if r["label"]}):
        idx = [i for i, r in enumerate(rows) if r["label"] and r.get("chain", "eth") == ch]
        k = int(flag[idx].sum()); lo, hi = wilson(k, len(idx))
        out.append(f"  {ch:5s} {k}/{len(idx)} = {k / len(idx):.1%}  [95% CI {lo:.1%}-{hi:.1%}]")
    k_all = int(flag[y == 1].sum()); n_all = int((y == 1).sum()); lo, hi = wilson(k_all, n_all)
    out.append(f"  all   {k_all}/{n_all} = {k_all / n_all:.1%}  [95% CI {lo:.1%}-{hi:.1%}]")

    if any("cat" in r for r in rows):
        out.append("By exploit category (exploits caught | false alarms on that category's normals):")
        for cat in sorted({r.get("cat", "?") for r in rows}):
            ex = [i for i, r in enumerate(rows) if r.get("cat") == cat and r["label"]]
            nm = [i for i, r in enumerate(rows) if r.get("cat") == cat and not r["label"]]
            ke, kn = int(flag[ex].sum()), int(flag[nm].sum())
            el, eh = wilson(ke, len(ex)); fl, fh = wilson(kn, len(nm))
            es = f"{ke}/{len(ex)} = {ke / len(ex):.1%} [{el:.0%}-{eh:.0%}]" if ex else "no exploits"
            ns = f"{kn}/{len(nm)} = {kn / len(nm):.2%} [{fl:.2%}-{fh:.2%}]" if nm else "no normals"
            out.append(f"  {cat:14s} caught {es:32s} | false alarms {ns}")
    out.append("False alarms on normals, by chain:")
    fpr_by_chain = {}
    for ch in sorted({r.get("chain", "eth") for r in rows if not r["label"]}):
        idx = [i for i, r in enumerate(rows) if not r["label"] and r.get("chain", "eth") == ch]
        k = int(flag[idx].sum()); lo, hi = wilson(k, len(idx))
        fpr_by_chain[ch] = (k, len(idx))
        out.append(f"  {ch:5s} {k}/{len(idx)} = {k / len(idx):.2%}  [95% CI {lo:.2%}-{hi:.2%}]  "
                   f"= {k / len(idx) * 1e6:,.0f} false alerts per million")
    by_src = defaultdict(lambda: [0, 0])
    for r, f in zip(rows, flag):
        if not r["label"]:
            key = f"{r.get('chain', 'eth')}:{r.get('source', '?')}"
            by_src[key][0] += int(f); by_src[key][1] += 1
    out.append("False alarms by normal source (flagged/total):")
    for kk in sorted(by_src, key=lambda s: (-by_src[s][0], s)):
        out.append(f"  {kk:34s} {by_src[kk][0]:3d}/{by_src[kk][1]:4d}")

    rec = k_all / n_all
    neg_k = sum(v[0] for v in fpr_by_chain.values()); neg_n = sum(v[1] for v in fpr_by_chain.values())
    fpr = neg_k / neg_n
    fpr_hi = wilson(neg_k, neg_n)[1]
    out.append(f"Precision vs exploit prevalence (recall {rec:.1%}, FPR {fpr:.3%}; upper-CI FPR {fpr_hi:.3%}):")
    for prev in (1e-1, 1e-2, 1e-3, 1e-4):
        p1 = rec * prev / (rec * prev + fpr * (1 - prev)) if fpr > 0 else 1.0
        p2 = rec * prev / (rec * prev + fpr_hi * (1 - prev))
        out.append(f"  1 exploit per {int(1 / prev):>6,} txs -> precision {p1:.1%} (pessimistic {p2:.1%})")
    tp, fp = int((flag & (y == 1)).sum()), int((flag & (y == 0)).sum())
    out.append(f"(footnote: pooled precision on this chain-mixed set = {tp}/{tp + fp} = {tp / max(1, tp + fp):.1%}; "
               f"not a deployment number)")
    text = "\n".join(out)
    print(text)
    (ROOT / "runs" / f"{args.name}_report_{args.tag}.txt").write_text(text + "\n")
    errs = [{"kind": "FP" if f else "FN", "p": round(float(pi), 3), "tx": r["tx_hash"], "incident": r["incident"],
             "chain": r.get("chain", "eth"), "source": r.get("source"), "category": r.get("category"),
             "target": r["card"].get("target"), "signer_side_net": r["card"].get("signer_side_net")}
            for r, pi, f in zip(rows, p, flag) if bool(f) != bool(r["label"])]
    (ROOT / "runs" / f"{args.name}_errors_{args.tag}.jsonl").write_text("".join(json.dumps(e) + "\n" for e in errs))


if __name__ == "__main__":
    main()
