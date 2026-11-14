"""Classical NEAR code-risk models under the shared nested grouped-CV protocol (near.model.eval_common).

Candidates: logistic regression and SGD (log loss) on [analyzer features | token 1-3 gram hashes | char 3-5 gram
hashes]; histogram gradient boosting on [analyzer features | SVD of token hashes]; the average of the best two.
Hyperparameters are picked on inner group folds (eval_common.selection_score). A vuln_class head (multinomial
logistic regression on label-1 rows) is scored by macro-F1 on real rows. Train only; never reads the sealed test.

    uv run python -m near.model.train_classic                  # full train_v1 minus split-audit drops
    uv run python -m near.model.train_classic --small --candidates sgd

Freeze: fit_model(kind, params, A, T, C, y, w) on all train with `final_selection` params from classic_cv.json,
features from load_train + featurize_rows, thresholds from the final OOF scores (also in the json).
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import time
from collections import Counter
from multiprocessing import get_context

import numpy as np
import scipy.sparse as sp
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import f1_score
from threadpoolctl import threadpool_limits

from near.analyzer.features import FEATURE_KEYS, VULN_CLASSES
from near.model import eval_common as ec
from near.model import featurize as fz

DATA = "near/data"
DROP_FILE = f"{DATA}/split_audit_v1_drop_ids.json"
REPORTS = "near/model/reports"
GRIDS = {  # sized from a 2-fold pilot (scratch); info = weight of severity-info real rows (0.3 = field weight, 0 = drop)
    "logreg": [{"C": c, "char": wc, "info": 0.3} for c, wc in itertools.product((0.3, 1.0), (0.0, 1.0))],
    "sgd": [{"alpha": a, "char": wc, "info": 0.3} for a, wc in itertools.product((3e-6, 1e-5, 3e-5), (0.0, 1.0))],
    "hgb": [dict(p, info=iw) for p, iw in itertools.product(
        ({"lr": 0.1, "leaves": 31, "svd": 0, "top_tokens": 1000}, {"lr": 0.1, "leaves": 31, "svd": 128},
         {"lr": 0.05, "leaves": 63, "iters": 600, "svd": 0, "top_tokens": 1000}), (0.3, 0.0))],
    "detectors": [{"info": 0.3}],  # no fitting: max detector severity, then hit count
}
SVD_DIM = 128
_G: dict = {}  # rows and feature matrices shared with forked workers


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load_train(path: str = f"{DATA}/train_v1.jsonl", drop_file: str = DROP_FILE,
               full: str = f"{DATA}/train_v1.jsonl") -> tuple[list[dict], dict]:
    """Train rows minus the split audit's leak drops; refuses a drop file made for another train_v1 (`full`, of which
    train_v1_small is a subset) and refuses test files."""
    if "test" in os.path.basename(path):
        raise SystemExit("refusing to read a test file in the training stage")
    with open(path) as f:
        rows = [json.loads(line) for line in f]
    info = {"train_file": path, "train_sha256": sha256(path), "n_raw": len(rows), "dropped": 0}
    if os.path.exists(drop_file):
        with open(drop_file) as f:
            d = json.load(f)
        if d["train_sha256"] != sha256(full):
            raise SystemExit(f"{drop_file} was made for another train_v1.jsonl")
        drop = set(d["ids"])
        rows = [r for r in rows if r["id"] not in drop]
        info.update(dropped=info["n_raw"] - len(rows), drop_file=drop_file, drop_file_sha256=sha256(drop_file))
    return rows, info


def featurize_rows(rows: list[dict], workers: int = 16):
    fz.fill_context(rows)
    A = fz.analyzer_matrix(rows, workers)
    T, C = fz.text_matrices(rows, workers)
    return A, T, C


def _weights(rows, info):
    return ec.sample_weights(rows, info_weight=info)


def fit_model(kind: str, p: dict, A, T, C, y, w, seed: int = ec.SEED) -> dict:
    """Fit one candidate on the given rows' features; returns a plain dict model for predict_model."""
    amax = np.maximum(np.abs(A).max(axis=0), 1e-9)
    if kind == "detectors":
        return {"kind": kind, "params": p}
    if kind in ("logreg", "sgd"):
        X = _linear_X(A, T, C, amax, p["char"])
        if kind == "logreg":
            clf = LogisticRegression(C=p["C"], solver="liblinear", max_iter=200)
        else:
            clf = SGDClassifier(loss="log_loss", alpha=p["alpha"], max_iter=50, tol=1e-3, random_state=seed)
        clf.fit(X, y, sample_weight=w)
        return {"kind": kind, "params": p, "amax": amax, "clf": clf}
    if kind == "hgb":
        m = {"kind": kind, "params": p}
        if p.get("svd", SVD_DIM):
            m["svd"] = TruncatedSVD(p.get("svd", SVD_DIM), algorithm="randomized", n_iter=4, random_state=seed).fit(T)
        if p.get("top_tokens"):
            m["tokens"] = SelectKBest(chi2, k=p["top_tokens"]).fit(T, y).get_support(indices=True)
        clf = HistGradientBoostingClassifier(learning_rate=p["lr"], max_leaf_nodes=p["leaves"],
                                             max_iter=p.get("iters", 300), l2_regularization=1.0,
                                             early_stopping=False, random_state=seed)
        m["clf"] = clf.fit(_hgb_X(m, A, T), y, sample_weight=w)
        return m
    raise ValueError(kind)


def _linear_X(A, T, C, amax, wc):
    blocks = [sp.csr_matrix((A / amax).astype(np.float32)), T]
    if wc:
        blocks.append(C * np.float32(wc))
    return sp.hstack(blocks, format="csr")


def _hgb_X(m: dict, A, T) -> np.ndarray:
    blocks = [A]
    if "svd" in m:
        blocks.append(m["svd"].transform(T))
    if "tokens" in m:
        blocks.append((T[:, m["tokens"]] > 0).toarray().astype(np.float32))
    return np.hstack(blocks)


def predict_model(m: dict, A, T, C) -> np.ndarray:
    if m["kind"] == "detectors":
        return A[:, FEATURE_KEYS.index("max_severity")] + 0.01 * A[:, FEATURE_KEYS.index("n_hits")]
    if m["kind"] == "hgb":
        return m["clf"].predict_proba(_hgb_X(m, A, T))[:, 1]
    return m["clf"].predict_proba(_linear_X(A, T, C, m["amax"], m["params"]["char"]))[:, 1]


def _fit_score(job):
    kind, p, tr, te = job
    rows, A, T, C, y = _G["rows"], _G["A"], _G["T"], _G["C"], _G["y"]
    m = fit_model(kind, p, A[tr], T[tr], C[tr], y[tr], _weights([rows[i] for i in tr], p["info"]))
    return predict_model(m, A[te], T[te], C[te])


def _limit_threads(n: int = 1):
    threadpool_limits(n)  # HGB/BLAS would otherwise start a thread per core in every worker


def _run(jobs, workers):
    """Every fit runs in a forked child: the parent never starts OpenMP/BLAS threads, which would deadlock later
    forks (libomp is not fork-safe)."""
    if workers <= 0:
        return [_fit_score(j) for j in jobs]
    n = min(max(workers, 1), len(jobs))
    with get_context("fork").Pool(n, initializer=_limit_threads, initargs=(max(1, workers // n),)) as pool:
        return pool.map(_fit_score, jobs, chunksize=1)


def select(kind: str, rows, tr, inner_folds, workers):
    """Inner-fold grid search; returns (best params, its OOF scores over tr, per-config selection scores)."""
    grid = GRIDS[kind]
    jobs = [(kind, p, itr, ite) for p in grid for itr, ite in inner_folds]
    preds = _run(jobs, workers)
    pos = {int(i): k for k, i in enumerate(tr)}
    sub = [rows[i] for i in tr]
    table = []
    for gi, p in enumerate(grid):
        oof = np.full(len(tr), np.nan)
        for fi, (_, ite) in enumerate(inner_folds):
            oof[[pos[int(i)] for i in ite]] = preds[gi * len(inner_folds) + fi]
        table.append((ec.selection_score(sub, oof), gi, oof))
    best = max(table, key=lambda t: (t[0], -t[1]))
    return grid[best[1]], best[2], [(grid[g], round(s, 4)) for s, g, _ in table]


def candidate(kind: str, workers: int, store: dict):
    def fit_predict(rows, tr, te, inner_folds):
        t0 = time.time()
        p, oof, table = select(kind, rows, tr, inner_folds, workers)
        scores = _run([(kind, p, tr, te)], workers)[0]
        store[te.tobytes()] = {"scores": scores, "train_oof": oof}
        print(f"    {kind}: selected {p} in {time.time() - t0:.0f}s; grid {table}", flush=True)
        return {"scores": scores, "train_oof": oof, "params": p}
    return fit_predict


def average_of(stores: list[dict]):
    def fit_predict(rows, tr, te, inner_folds):
        parts = [s[te.tobytes()] for s in stores]
        return {"scores": np.mean([p["scores"] for p in parts], axis=0),
                "train_oof": np.mean([p["train_oof"] for p in parts], axis=0)}
    return fit_predict


def class_head(rows, A, T, folds, C_reg: float = 1.0) -> dict:
    """vuln_class head: multinomial LR on label-1 rows of each outer-train fold, scored on real label-1 rows of the
    outer-test fold. Baseline: the class with the most detector hits (logic_error when none fire)."""
    y = np.array([r.get("vuln_class") or "" for r in rows], object)
    pos = np.array([r["label"] == 1 and bool(r.get("vuln_class")) for r in rows])
    real = np.array([ec.is_real(r) for r in rows])
    w_all = ec.sample_weights(rows)
    hit_cols = [FEATURE_KEYS.index(f"hit_{c}") for c in VULN_CLASSES]
    pred = np.array([""] * len(rows), object)
    base = np.array([""] * len(rows), object)
    X = sp.hstack([sp.csr_matrix(A / np.maximum(np.abs(A).max(axis=0), 1e-9)), T], format="csr")
    for tr, te in folds:
        trp, tep = tr[pos[tr]], te[pos[te] & real[te]]
        clf = LogisticRegression(C=C_reg, max_iter=300)
        clf.fit(X[trp], y[trp], sample_weight=w_all[trp])
        pred[tep] = clf.predict(X[tep])
    for i in np.where(pos & real)[0]:
        h = A[i, hit_cols]
        base[i] = VULN_CLASSES[int(np.argmax(h))] if h.max() > 0 else "logic_error"
    ev = pos & real
    labels = sorted(set(y[ev]))
    rep = {}
    for name, p in (("model", pred), ("detector_baseline", base)):
        rep[name] = {"macro_f1": float(f1_score(y[ev], p[ev], labels=labels, average="macro", zero_division=0)),
                     "accuracy": float((y[ev] == p[ev]).mean()),
                     "per_class_f1": dict(zip(labels, map(float, f1_score(y[ev], p[ev], labels=labels, average=None,
                                                                          zero_division=0))))}
    rep["n_real"] = int(ev.sum())
    rep["class_counts_real"] = dict(Counter(y[ev]))
    return rep


def final_selection(kind: str, rows, workers: int, inner: int, seed: int, out: str | None = None) -> dict:
    """Params for the freeze: the same inner grid search run over all train (grouped folds), plus the thresholds
    from its OOF scores (saved to {out}_final_{kind}_oof.npy so an ensemble's thresholds can be derived)."""
    tr = np.arange(len(rows))
    folds = ec.group_folds(rows, inner, seed + 100)
    p, oof, table = select(kind, rows, tr, folds, workers)
    if out:
        np.save(f"{out}_final_{kind}_oof.npy", oof)
    return {"params": p, "oof_thresholds": ec.thresholds_from(rows, oof), "grid": table,
            "oof_metrics": ec.metrics(rows, oof)}


def components(name: str) -> list[str]:
    return name[4:-1].split(",") if name.startswith("avg(") else [name]


def final_only(out: str, workers: int) -> None:
    """Run the all-train selection for the best candidate's components; an ensemble gets thresholds from the mean
    of its components' OOF scores."""
    with open(f"{out}.json") as f:
        rep = json.load(f)
    rows, _ = load_train(rep["data"]["train_file"])
    A, T, C = featurize_rows(rows, workers)
    _G.update(rows=rows, A=A, T=T, C=C, y=np.array([r["label"] for r in rows]))
    pr, best = rep["protocol"], rep["best"]
    fin = rep.setdefault("final_selection", {})
    for kind in components(best):
        print(f"== final selection on all train: {kind}", flush=True)
        fin[kind] = _jsonable(final_selection(kind, rows, workers, pr["inner"], pr["seed"], out))
    if len(components(best)) > 1:
        oof = np.mean([np.load(f"{out}_final_{k}_oof.npy") for k in components(best)], axis=0)
        fin[best] = _jsonable({"params": {k: fin[k]["params"] for k in components(best)},
                               "oof_thresholds": ec.thresholds_from(rows, oof), "oof_metrics": ec.metrics(rows, oof)})
    with open(f"{out}.json", "w") as f:
        json.dump(rep, f, indent=1)
    with open(f"{out}.md", "w") as f:
        f.write(render_md(rep))


def _jsonable(o):
    if isinstance(o, dict):
        return {str(k): _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsonable(v) for v in o]
    if isinstance(o, (np.floating, float)):
        return None if not np.isfinite(o) else float(o)
    if isinstance(o, np.integer):
        return int(o)
    return o


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--small", action="store_true", help="train_v1_small.jsonl instead of train_v1.jsonl")
    ap.add_argument("--candidates", default="hgb,sgd,logreg,detectors")
    ap.add_argument("--outer", type=int, default=5)
    ap.add_argument("--inner", type=int, default=3)
    ap.add_argument("--seed", type=int, default=ec.SEED)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--out", default=f"{REPORTS}/classic_cv")
    ap.add_argument("--sample-groups", type=int, default=0, help="smoke runs: keep only this many random groups")
    ap.add_argument("--rescore", action="store_true", help="only recompute metrics/markdown from saved OOF scores")
    ap.add_argument("--final-only", action="store_true", help="only the all-train selection for the best candidate")
    ap.add_argument("--no-final", action="store_true", help="skip the all-train selection for the freeze")
    args = ap.parse_args()
    if args.rescore:
        return rescore(args.out)
    if args.final_only:
        return final_only(args.out, args.workers)

    rows, info = load_train(f"{DATA}/train_v1_small.jsonl" if args.small else f"{DATA}/train_v1.jsonl")
    if args.sample_groups:
        keep = set(np.random.RandomState(0).permutation(sorted({r["group"] for r in rows}))[:args.sample_groups])
        rows = [r for r in rows if r["group"] in keep]
        info["sample_groups"] = args.sample_groups
    t0 = time.time()
    A, T, C = featurize_rows(rows, args.workers)
    y = np.array([r["label"] for r in rows])
    _G.update(rows=rows, A=A, T=T, C=C, y=y)
    print(f"{len(rows)} rows ({info['dropped']} dropped by split audit), {int(y.sum())} label-1, "
          f"{len({r['group'] for r in rows})} groups; featurized in {time.time() - t0:.0f}s "
          f"(context: {dict(Counter(r['context_from'] for r in rows))})", flush=True)

    report = {"data": info, "protocol": {"outer": args.outer, "inner": args.inner, "seed": args.seed,
                                         "levels_fpr_on_contract_corpus": ec.LEVELS, "grids": GRIDS,
                                         "selection": ec.selection_score.__doc__.strip()},
              "context_from": dict(Counter(r["context_from"] for r in rows)), "candidates": {}}
    stores = {}
    for kind in args.candidates.split(","):
        print(f"== {kind}", flush=True)
        t1 = time.time()
        stores[kind] = {}
        out = ec.nested_group_cv(candidate(kind, args.workers, stores[kind]), rows, args.outer, args.inner, args.seed)
        report["candidates"][kind] = {"metrics": ec.metrics(rows, out["scores"], out["decisions"]),
                                      "fold_thresholds": out["thresholds"], "fold_params": out["params"],
                                      "seconds": round(time.time() - t1)}
        np.save(f"{args.out}_{kind}_oof.npy", out["scores"])
        print(summary_line(kind, report["candidates"][kind]["metrics"]), flush=True)
    kinds = [k for k in stores if k != "detectors"]
    if len(kinds) >= 2:
        best2 = sorted(kinds, key=lambda k: -_rank_key(report["candidates"][k]["metrics"]))[:2]
        name = f"avg({best2[0]},{best2[1]})"
        out = ec.nested_group_cv(average_of([stores[k] for k in best2]), rows, args.outer, args.inner, args.seed)
        report["candidates"][name] = {"metrics": ec.metrics(rows, out["scores"], out["decisions"]),
                                      "fold_thresholds": out["thresholds"]}
        np.save(f"{args.out}_{name}_oof.npy", out["scores"])
        print(summary_line(name, report["candidates"][name]["metrics"]), flush=True)

    folds = ec.group_folds(rows, args.outer, args.seed)
    with get_context("fork").Pool(1, initializer=_limit_threads, initargs=(args.workers,)) as pool:
        report["class_head"] = pool.apply(class_head, (rows, A, T, folds))
    print(f"class head macro-F1 on real rows {report['class_head']['model']['macro_f1']:.3f} "
          f"(detector baseline {report['class_head']['detector_baseline']['macro_f1']:.3f})", flush=True)

    best = max(report["candidates"], key=lambda k: _rank_key(report["candidates"][k]["metrics"]))
    report["best"] = best
    if not args.no_final:
        for kind in components(best):
            print(f"== final selection on all train: {kind}", flush=True)
            report.setdefault("final_selection", {})[kind] = final_selection(kind, rows, args.workers, args.inner,
                                                                             args.seed, args.out)
    json.dump(_jsonable(report), open(f"{args.out}.json", "w"), indent=1)
    open(f"{args.out}.md", "w").write(render_md(report))
    print(f"wrote {args.out}.json / .md; best by protocol: {best}")


def rescore(out: str) -> None:
    """Recompute metrics and the markdown from saved OOF scores + per-fold thresholds with the current
    eval_common (folds are deterministic from the seed). Ensembles are the mean of their components' scores."""
    with open(f"{out}.json") as f:
        rep = json.load(f)
    rows, _ = load_train(rep["data"]["train_file"])
    fz.fill_context(rows)
    folds = ec.group_folds(rows, rep["protocol"]["outer"], rep["protocol"]["seed"])
    fold_of = np.zeros(len(rows), int)
    for k, (_, te) in enumerate(folds):
        fold_of[te] = k
    for name, c in rep["candidates"].items():
        s = np.mean([np.load(f"{out}_{k}_oof.npy") for k in components(name)], axis=0)
        dec = {lvl: s >= np.array([np.inf if t is None else t for t in c["fold_thresholds"][lvl]])[fold_of]
               for lvl in ec.LEVELS}
        c["metrics"] = _jsonable(ec.metrics(rows, s, dec))
    fin, best = rep.get("final_selection", {}), rep["best"]
    finals = [f"{out}_final_{k}_oof.npy" for k in components(best)]
    if len(finals) > 1 and all(os.path.exists(p) for p in finals):
        oof = np.mean([np.load(p) for p in finals], axis=0)
        fin[best] = _jsonable({"params": {k: fin[k]["params"] for k in components(best)},
                               "oof_thresholds": ec.thresholds_from(rows, oof), "oof_metrics": ec.metrics(rows, oof)})
    with open(f"{out}.json", "w") as f:
        json.dump(rep, f, indent=1)
    with open(f"{out}.md", "w") as f:
        f.write(render_md(rep))


def _rank_key(m: dict) -> float:
    """Candidate ranking: the inner selection objective's outer analogue (warn level)."""
    w = m["warn"]
    return 0.75 * np.nan_to_num(w["recall_real_noninfo"]["rate"]) + 0.25 * np.nan_to_num(w["recall_mutation"]["rate"])


def summary_line(name: str, m: dict) -> str:
    parts = [f"{name}: PR-AUC {m['pr_auc']:.3f} ROC-AUC {m['roc_auc']:.3f}"]
    for lvl in ec.LEVELS:
        x = m[lvl]
        parts.append(f"{lvl}: real {ec.fmt_rate(x['recall_real_noninfo'])} mut {ec.fmt_rate(x['recall_mutation'])} "
                     f"FPR-contract {ec.fmt_rate(x['fpr_corpus_contract'])} files {ec.fmt_rate(x['contract_alarm_share'])}")
    return "\n  ".join(parts)


ROWS = [("recall, real label-1 (all)", "recall_real"), ("recall, real label-1 severity != info", "recall_real_noninfo"),
        ("recall, real label-1 severity = info", "recall_real_info"), ("recall, mutations", "recall_mutation"),
        ("false alarms, corpus negatives (all)", "fpr_corpus"),
        ("false alarms, contract-code corpus negatives", "fpr_corpus_contract"),
        ("false alarms, paired fixed versions (real)", "fpr_paired_fixed"),
        ("false alarms, mutation originals", "fpr_mutation_original"),
        ("contract level: clean corpus files alarming", "contract_alarm_share"),
        ("contract level: files holding a real vulnerability alarming", "contract_recall_real")]


def _thr(c: dict, lvl: str) -> str:
    t = [x for x in c.get("fold_thresholds", {}).get(lvl, []) if x is not None]
    return f"median {np.median(t):.4f} (folds {min(t):.4f}-{max(t):.4f})" if t else "n/a"


def render_md(rep: dict) -> str:
    d, pr = rep["data"], rep["protocol"]
    out = ["# Classical models: nested grouped CV on train (NEAR code risk)", "",
           f"Data: `{d['train_file']}` sha256 `{d['train_sha256'][:16]}...`, {d['n_raw']} rows, {d['dropped']} dropped by "
           f"the split audit's leak list; sealed test not read. Outer {pr['outer']}-fold / inner {pr['inner']}-fold "
           f"GroupKFold over `group`, seed {pr['seed']}. Thresholds per outer fold from inner out-of-fold scores: "
           "block = 1% and warn = 5% per-function FPR on contract-code corpus negatives (not async, not test or "
           "off-chain paths). Rates pooled over outer folds, Wilson 95% CIs. Function context: "
           f"{rep['context_from']}.", "", f"Selection objective (inner folds): {' '.join(pr['selection'].split())}", ""]
    out += ["## Ranking summary", "", "| candidate | PR-AUC | ROC-AUC | ROC-AUC real vs contract corpus | "
            "ROC-AUC real vs fixed | pair rank acc (vuln > fixed, ties half) | warn: real non-info recall | warn: FPR contract corpus |",
            "|---|---|---|---|---|---|---|---|"]
    for name, c in rep["candidates"].items():
        m = c["metrics"]
        out.append(f"| {name} | {m['pr_auc']:.3f} | {m['roc_auc']:.3f} | {m['roc_auc_real_vs_contract_corpus']:.3f} | "
                   f"{m['roc_auc_real_vs_fixed']:.3f} | {ec.fmt_rate(m['pair_rank_acc'])} | "
                   f"{ec.fmt_rate(m['warn']['recall_real_noninfo'])} | {ec.fmt_rate(m['warn']['fpr_corpus_contract'])} |")
    out += ["", f"Best by the protocol ranking (0.75 x warn real non-info recall + 0.25 x warn mutation recall): "
            f"**{rep['best']}**", ""]
    b = rep["candidates"][rep["best"]]["metrics"]
    for lvl, f in ec.LEVELS.items():
        x = b[lvl]
        out.append(f"- {lvl} (per-function FPR {f:.0%} target): real non-info recall {ec.fmt_rate(x['recall_real_noninfo'])}, "
                   f"mutation recall {ec.fmt_rate(x['recall_mutation'])}, contract-code corpus FPR "
                   f"{ec.fmt_rate(x['fpr_corpus_contract'])}, paired fixed FPR {ec.fmt_rate(x['fpr_paired_fixed'])}; "
                   f"clean files alarming {ec.fmt_rate(x['contract_alarm_share'])}, files with a real vulnerability "
                   f"alarming {ec.fmt_rate(x['contract_recall_real'])}.")
    out.append("")
    for name, c in rep["candidates"].items():
        m = c["metrics"]
        out += [f"## {name}", "", f"PR-AUC {m['pr_auc']:.3f} (weighted {m['pr_auc_weighted']:.3f}), ROC-AUC "
                f"{m['roc_auc']:.3f}, mutation vs contract corpus ROC-AUC {m['roc_auc_mutation_vs_contract_corpus']:.3f}."
                + (f" Params per outer fold: {c['fold_params']}." if c.get("fold_params") else ""), "",
                "| | block (FPR 1%) | warn (FPR 5%) |", "|---|---|---|",
                f"| threshold | {_thr(c, 'block')} | {_thr(c, 'warn')} |"]
        out += [f"| {label} | {ec.fmt_rate(m['block'][k])} | {ec.fmt_rate(m['warn'][k])} |" for label, k in ROWS]
        out += ["", "Recall per vuln_class on real label-1 rows:", "", "| class | block | warn |", "|---|---|---|"]
        out += [f"| {k} | {ec.fmt_rate(v)} | {ec.fmt_rate(m['warn']['recall_class_real'][k])} |"
                for k, v in m["block"]["recall_class_real"].items()]
        out.append("")
    ch = rep["class_head"]
    out += ["## vuln_class head (reasons)", "",
            f"Multinomial logistic regression on label-1 rows of each outer-train fold (analyzer + token hashes, "
            f"real rows upweighted), scored on {ch['n_real']} real label-1 rows of the outer-test folds.", "",
            "| | macro-F1 | accuracy |", "|---|---|---|"]
    out += [f"| {k} | {ch[k]['macro_f1']:.3f} | {ch[k]['accuracy']:.3f} |" for k in ("model", "detector_baseline")]
    out += ["", "| class | n real | F1 model | F1 detector baseline |", "|---|---|---|---|"]
    out += [f"| {k} | {ch['class_counts_real'].get(k, 0)} | {v:.2f} | {ch['detector_baseline']['per_class_f1'][k]:.2f} |"
            for k, v in ch["model"]["per_class_f1"].items()]
    for kind, f in rep.get("final_selection", {}).items():
        out += ["", f"## Freeze input: all-train selection for {kind}", "",
                f"Params {f['params']}; thresholds from grouped OOF scores on all train: "
                + ", ".join(f"{k} {v:.4f}" for k, v in f["oof_thresholds"].items())
                + ". Refit with `near.model.train_classic.fit_model` on all train rows (features from "
                "`load_train` + `featurize_rows`)."]
    out += ["", "## Limits", "", LIMITS]
    return "\n".join(out) + "\n"


LIMITS = """- Labels: the split audit found real label-1 train rows only ~50% plausible on a 40-row read (Wilson 35-65%);
  severity-info findings are 17% of train positives. Real-row recall here is measured against those noisy labels.
- Corpus negatives are presumed safe, not verified; a few are vulnerable (audit read 1 clear case in 40).
- Mutation rows are synthetic; their recall says the model learns the injected patterns, not real-world bugs.
- Per-class real counts are small (oracle_price 7, unguarded_upgrade 2, unchecked_receiver 5): wide CIs.
- Features use the function text only (no file context); 85 code_from_snippet real rows derive `is_public` from
  their own `pub` keyword and have no trait information.
- Thresholds are set on inner-fold models trained on less data than the outer model, as in scripts/eval_nested.py;
  realized outer FPRs land at 1.0% / 5.1-5.5% for the learned models.
- Vulnerable vs fixed versions of the same function are ranked at about chance (pair rank ~51-57%): the models
  mostly score what kind of code a function is (state-changing DeFi logic, callbacks, auth patterns), not whether the
  specific bug is present. Real-row recall against corpus negatives partly reflects that difference in code type.
- Contract-level recall uses corpus rows of the same (group, path), which may come from a later commit than the
  vulnerable function."""


if __name__ == "__main__":
    main()
