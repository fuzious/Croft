"""Freeze the NEAR code-risk model: HGB on analyzer features + chi2-selected code tokens, refit on all non-trivial
train_v1 rows (minus the split audit's leak ids), block / warn thresholds from grouped out-of-fold scores.

Model choice (nested CV only, near/model/reports/classic_cv.md and encoder_cv.md): plain hgb has the best real
non-info recall at the block level (58/376 = 15.4% vs 12.8% for avg(hgb,logreg) and 4.5% for the encoder) at the
same clean-file alarm share (4.4%); every encoder ensemble lowers block recall. Trivial functions (< 2 statements or
body < 3 lines) are excluded from training and from scoring (near.model.predict.model_scored): the corpus negatives
contain none, so a model trained on trivial mutations reads every one-line getter as vulnerable. `--cv` runs the
nested CV of that variant and the all-train selection whose params and OOF this freeze reuses.

    uv run python -m near.model.freeze --cv       # about 21 min; near/models/frozen_near_v1_cv.{json,_oof.npy,...}
    uv run python -m near.model.freeze            # about 3 min; writes near/models/frozen_near_v1.{pkl,json}

Mirrors scripts/freeze_v9.py: estimator stored separately from the metadata, sha256 of the feature code and of the
training rows (id, label), train ids file, split manifest sha; the artifact is reloaded and its predictions verified
(also through near.model.predict's own featurization path) before it is accepted.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pickle
import time
from collections import Counter, defaultdict

import numpy as np
import scipy.sparse as sp
from sklearn.linear_model import LogisticRegression

from near.analyzer.features import FEATURE_KEYS
from near.model import eval_common as ec
from near.model import featurize as fz
from near.model import predict
from near.model import train_classic as tc
from near.model.predict import code_files, manifest_path, sha256_file  # noqa: F401 (re-exported for callers)

OUT = "near/models"
TAG = "frozen_near_v1"
CLASSIC = "near/model/reports/classic_cv"
SPLIT_MANIFEST = "near/data/split_manifest_v1.json"
MODEL_NAME = ("hist gradient boosting (lr 0.1, 31 leaves, 300 iters, l2 1.0) on signed-log analyzer features + "
              "1000 chi2-selected binary code-token 1-3 grams")
CONTRACT_RULE = ("contract risk = max per-function risk over public, non-test, contract-code functions (not async, "
                 "not under test or off-chain dirs); label high if >= block threshold, medium if >= warn, else low")


def read_json(path):
    with open(path) as f:
        return json.load(f)


def write_json(path, obj) -> None:
    with open(path, "w") as f:
        json.dump(obj, f, indent=1)


def token_hash_spec() -> dict:
    """HashingVectorizer params with callables by name (repr would carry memory addresses)."""
    return json.loads(json.dumps({k: getattr(v, "__name__", v) if callable(v) else v
                                  for k, v in sorted(fz.TOKEN_HASH.get_params().items())}))


def rows_sha256(rows: list[dict]) -> str:
    """sha256 of the sorted (id, label) pairs: what was trained on, independent of row order and extra fields."""
    return hashlib.sha256(json.dumps(sorted([r["id"], int(r["label"])] for r in rows)).encode()).hexdigest()


def fit_class_head(rows: list[dict], A, T) -> dict:
    """vuln_class head as evaluated in train_classic.class_head: multinomial LR (C=1) on label-1 rows, features
    [analyzer / max-abs | token hashes], protocol sample weights. Coefficients stored sparse."""
    amax = np.maximum(np.abs(A).max(axis=0), 1e-9)
    pos = np.array([r["label"] == 1 and bool(r.get("vuln_class")) for r in rows])
    X = sp.hstack([sp.csr_matrix(A / amax), T], format="csr")[pos]
    y = np.array([r["vuln_class"] for r in rows], object)[pos]
    clf = LogisticRegression(C=1.0, max_iter=300).fit(X, y, sample_weight=ec.sample_weights(rows)[pos])
    clf.sparsify()
    return {"clf": clf, "amax": amax}


def build_artifact(rows: list[dict], A, T, params: dict, thresholds: dict, version: str) -> dict:
    y = np.array([r["label"] for r in rows])
    w = ec.sample_weights(rows, info_weight=params.get("info"))
    est = tc.fit_model("hgb", params, A, T, None, y, w)
    return {"estimator": est, "class_head": fit_class_head(rows, A, T), "thresholds": dict(thresholds),
            "version": version, "params": params}


def save_artifact(art: dict, out_dir: str, tag: str, meta: dict | None = None) -> str:
    """Write {tag}.pkl and its manifest {tag}.json (meta + pkl sha256 + feature-code sha256); returns the pkl path."""
    pkl = os.path.join(out_dir, f"{tag}.pkl")
    with open(pkl, "wb") as f:
        pickle.dump({k: v for k, v in art.items() if k != "info"}, f)
    man = dict(meta or {}, version=art["version"], thresholds=art["thresholds"], pkl_sha256=sha256_file(pkl),
               code_sha256=predict.code_hashes())
    write_json(manifest_path(pkl), man)
    return pkl


def contract_level(rows: list[dict], hit: np.ndarray, clean_by: str = "group") -> dict:
    """File-level alarms under the deployed aggregation rule (predict.counts_toward_contract), files = (group, path).
    clean_files: corpus files of groups with no real label-1 row (clean_by="group"), or corpus files holding no real
    label-1 row (clean_by="file": also inside audited groups, the only kind the sealed test has); real_vuln_files:
    files holding a real label-1 row, alarming if that row or a counted corpus function of the same file alarms
    (corpus may be a later commit)."""
    dirty = {r["group"] for r in rows if ec.is_real(r) and r["label"] == 1}
    clean, vuln = defaultdict(bool), {}
    for i, r in enumerate(rows):
        if ec.is_real(r) and r["label"] == 1:
            vuln[(r["group"], r["path"])] = vuln.get((r["group"], r["path"]), False) | bool(hit[i])
    for i, r in enumerate(rows):
        if r["source"] != "corpus" or r["label"] != 0 or not predict.counts_toward_contract(r):
            continue
        key = (r["group"], r["path"])
        if key in vuln:
            vuln[key] |= bool(hit[i])
        elif r["group"] not in dirty or clean_by == "file":
            clean[key] |= bool(hit[i])
    c, v = np.array(list(clean.values()), bool), np.array(list(vuln.values()), bool)
    return {"clean_files": ec.rate(c, np.ones(len(c), bool)), "real_vuln_files": ec.rate(v, np.ones(len(v), bool))}


def train_rows(which: str) -> tuple[list[dict], dict, np.ndarray]:
    """(rows to fit on, load info, trivial mask over all train rows); which = all | nontrivial."""
    rows, info = tc.load_train()
    triv = np.array([not predict.model_scored(r) for r in rows])
    return (rows if which == "all" else [r for r, t in zip(rows, triv) if not t]), info, triv


def cv_nontrivial(workers: int, out: str) -> None:
    """Nested grouped CV (train_classic's hgb grid and selection, eval_common protocol) for hgb fit on non-trivial
    rows only; metrics over all train rows with trivial rows never alarming (the deployed rule). Then the all-train
    selection for the freeze."""
    t0 = time.time()
    rows, info, triv = train_rows("nontrivial")
    full, _ = tc.load_train()
    A, T, C = tc.featurize_rows(rows, workers)
    tc._G.update(rows=rows, A=A, T=T, C=C, y=np.array([r["label"] for r in rows]))
    print(f"{len(rows)} non-trivial rows of {len(full)} ({int(triv.sum())} trivial dropped)", flush=True)
    res = ec.nested_group_cv(tc.candidate("hgb", workers, {}), rows, 5, 3, ec.SEED)
    s = np.full(len(full), -1.0)
    s[~triv] = res["scores"]
    dec = {lvl: np.zeros(len(full), bool) for lvl in ec.LEVELS}
    for lvl in ec.LEVELS:
        dec[lvl][~triv] = res["decisions"][lvl]
    m = ec.metrics(full, s, dec)
    np.save(f"{out}_oof.npy", s)
    print(tc.summary_line("hgb nontrivial", m), flush=True)
    fin = tc.final_selection("hgb", rows, workers, 3, ec.SEED, out)
    rep = {"data": info, "n_trivial": int(triv.sum()), "metrics": m, "fold_thresholds": res["thresholds"],
           "fold_params": res["params"], "final_selection": {"hgb": fin}, "seconds": round(time.time() - t0)}
    write_json(f"{out}.json", tc._jsonable(rep))
    print(f"wrote {out}.json; final params {fin['params']}; {time.time() - t0:.0f}s")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--tag", default=TAG)
    ap.add_argument("--train", choices=["nontrivial", "all"], default="nontrivial")
    ap.add_argument("--cv", action="store_true", help="run the non-trivial nested CV + all-train selection only")
    args = ap.parse_args()
    if args.cv:
        return cv_nontrivial(args.workers, f"{OUT}/{args.tag}_cv")
    t0 = time.time()
    sel_prefix = CLASSIC if args.train == "all" else f"{OUT}/{args.tag}_cv"
    cv, classic = read_json(f"{sel_prefix}.json"), read_json(f"{CLASSIC}.json")
    params = cv["final_selection"]["hgb"]["params"]
    rows, info, triv = train_rows(args.train)
    A, T, C = tc.featurize_rows(rows, args.workers)
    y = np.array([r["label"] for r in rows])
    print(f"{len(rows)} train rows, {int(y.sum())} label-1; featurized in {time.time() - t0:.0f}s; params {params}",
          flush=True)

    tc._G.update(rows=rows, A=A, T=T, C=C, y=y)
    folds = ec.group_folds(rows, 3, ec.SEED + 100)  # the folds of train_classic.final_selection
    oof = np.full(len(rows), np.nan)
    for (_, ite), s in zip(folds, tc._run([("hgb", params, itr, ite) for itr, ite in folds], args.workers)):
        oof[ite] = s
    assert np.isfinite(oof).all(), "OOF scores missing"
    sel = np.load(f"{sel_prefix}_final_hgb_oof.npy")
    oof_matches = bool(np.allclose(oof, sel, atol=1e-9))
    thr = ec.thresholds_from(rows, oof)
    full = tc.load_train()[0] if args.train == "nontrivial" else rows
    s_full = np.full(len(full), -1.0)  # deployed rule: trivial functions never alarm
    s_full[~triv] = oof[~triv] if args.train == "all" else oof
    m = ec.metrics(full, s_full, {lvl: s_full >= t for lvl, t in thr.items()})
    contract = {lvl: contract_level(full, s_full >= t) for lvl, t in thr.items()}
    print(f"OOF thresholds {thr} (same OOF as the selection run: {oof_matches})", flush=True)

    art = build_artifact(rows, A, T, params, thr, args.tag)  # parent fits only after all forks are done
    ids_path = os.path.join(OUT, f"{args.tag}_train_ids.json")
    write_json(ids_path, sorted(r["id"] for r in rows))
    src = Counter(r["source"] for r in rows if r["label"] == 1)
    meta = {
        "model_name": MODEL_NAME, "params": params, "created": datetime.date.today().isoformat(),
        "feature_schema": {"analyzer_keys": list(FEATURE_KEYS), "token_dim": fz.TOKEN_DIM,
                           "token_hash": token_hash_spec(), "selected_tokens": len(art["estimator"]["tokens"]),
                           "hgb_columns": int(art["estimator"]["clf"].n_features_in_)},
        "class_head": {"classes": [str(c) for c in art["class_head"]["clf"].classes_],
                       "cv_macro_f1_real": classic["class_head"]["model"]["macro_f1"],
                       "cv_detector_baseline_macro_f1_real": classic["class_head"]["detector_baseline"]["macro_f1"]},
        "levels_fpr_on_contract_corpus": ec.LEVELS,
        "oof_metrics_note": "OOF metrics over all train rows, trivial functions never alarming (deployed rule)",
        "threshold_source": "grouped 3-fold OOF scores on all fitted train rows (same folds and params as the all-train "
                            "selection); lowest score with <= 1% / 5% of contract-code corpus negatives above it",
        "oof_matches_selection_run": oof_matches, "contract_rule": CONTRACT_RULE,
        "oof": {"pr_auc": m["pr_auc"], "roc_auc": m["roc_auc"],
                **{lvl: {k: m[lvl][k] for k in ("recall_real_noninfo", "recall_mutation", "fpr_corpus_contract",
                                                "fpr_paired_fixed")} | contract[lvl] for lvl in ec.LEVELS}},
        "nested_cv": {k: (cv["candidates"]["hgb"]["metrics"] if args.train == "all" else cv["metrics"])[k][
            "recall_real_noninfo"] for k in ec.LEVELS},
        "train_rows": len(rows), "train_positives": int(y.sum()), "train_positives_by_source": dict(src),
        "train_groups": len({r["group"] for r in rows}),
        "train_rows_sha256": rows_sha256(rows), "train_file": info["train_file"],
        "train_file_sha256": info["train_sha256"], "drop_file": info["drop_file"],
        "drop_file_sha256": info["drop_file_sha256"], "dropped": info["dropped"],
        "train_ids_file": ids_path, "train_ids_sha256": sha256_file(ids_path),
        "split_manifest": SPLIT_MANIFEST, "split_manifest_sha256": sha256_file(SPLIT_MANIFEST),
        "selection_json": f"{sel_prefix}.json", "selection_json_sha256": sha256_file(f"{sel_prefix}.json"),
        "train_subset": args.train, "trivial_rows_excluded": int(triv.sum()) if args.train == "nontrivial" else 0,
        "seed": ec.SEED,
    }
    pkl = save_artifact(art, OUT, args.tag, meta)

    back = predict.load(pkl, cache=False)
    s0 = tc.predict_model(art["estimator"], A, T, None)
    assert np.allclose(tc.predict_model(back["estimator"], A, T, None), s0), "reload mismatch"
    g0, _ = predict.class_guess(art["class_head"], A[:2000], T[:2000])
    assert predict.class_guess(back["class_head"], A[:2000], T[:2000])[0] == g0, "class head reload mismatch"
    ok = np.array([predict.model_scored(r) for r in rows])
    idx = np.random.RandomState(ec.SEED).choice(np.where(ok)[0], 1000, replace=False)
    via = predict.score_functions([rows[i] for i in idx], back)
    assert np.allclose([v["risk"] for v in via], s0[idx], atol=1e-6), "predict.py featurization differs from training"
    print(json.dumps({k: v for k, v in read_json(manifest_path(pkl)).items()
                      if k not in ("feature_schema", "code_sha256", "oof")}, indent=1))
    print(f"wrote {pkl} ({os.path.getsize(pkl) / 2**20:.1f} MB); reload and predict-path checks passed; "
          f"{time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
