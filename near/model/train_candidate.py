"""Bounded code-model experiment on train_v2 only; never reads the historical test sets.

Run: uv run python -m near.model.train_candidate [--cache-dir PATH]
The JSON protocol is written before fitting. Candidates are research artifacts, not served models.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import pickle
import platform
import re
import time
from pathlib import Path

import numpy as np
from threadpoolctl import threadpool_limits

from near.collect.extract_corpus import is_trivial
from near.model import eval_common as ec
from near.model import train_classic_v2 as tc

ROOT = Path(__file__).resolve().parents[2]
TRAIN = ROOT / "near/data/train_v2.jsonl"
REPORT = ROOT / "near/model/reports/training_candidate.json"
ARTIFACT = ROOT / "near/models/code_candidate.pkl"
SEED = 20261115
CANDIDATES = {
    "baseline": dict(tc.V1_PARAMS),
    "real_weighted": dict(tc.V1_PARAMS, lr=0.07, leaves=15, iters=400, min_leaf=40,
                          top_tokens=500, r2m=2.0, mut=0.25, fixed=3.0),
    "pair_focused": dict(tc.V1_PARAMS, lr=0.07, leaves=15, iters=400, min_leaf=40,
                         top_tokens=0, r2m=3.0, mut=0.1, fixed=5.0),
    "regularized": dict(tc.V1_PARAMS, lr=0.05, leaves=15, iters=400, min_leaf=80,
                        top_tokens=500, mut=0.5, fixed=3.0),
}
PROTOCOL = {
    "seed": SEED,
    "data": "train_v2 only; test_v1/test_v1c are never read",
    "split": "Union repository groups with identical nontrivial whitespace-stripped code (conservative: also "
             "strips whitespace inside literals). Five row-balanced component folds: 0+1 fit, 2 calibrate, "
             "3 select, 4 validate. Bootstrap the same merged components.",
    "features": "Existing context-no-era feature blocks and token hashes; no fitted transform sees held-out rows.",
    "candidates": CANDIDATES,
    "thresholds": "Calibration corpus contract negatives: <=1% high, <=5% medium-or-higher.",
    "selection": "On selection groups, eligible when high FPR <=2%, medium FPR <=7.5%, and fixed high FPR "
                 "<= baseline +5 percentage points. Maximize real non-info high recall, then medium recall, "
                 "then minimize fixed high FPR; exact ties retain baseline.",
    "adoption": "On final development-validation groups: at least +3 percentage points real high recall, "
                "paired repository-group bootstrap 95% lower bound >0, no medium recall loss, high FPR "
                "<=max(1.5%,baseline+0.2pp), medium FPR <=max(6%,baseline+0.5pp), and fixed high FPR "
                "<=baseline+3pp. Otherwise retain baseline. This is not a new sealed-test result.",
}


def sha(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def provenance(feature_hashes, train_sha, cache_dir):
    code = dict(feature_hashes)
    for relative in ("near/model/train_candidate.py", "near/model/train_classic_v2.py",
                     "near/model/eval_common.py", "near/collect/extract_corpus.py"):
        code[relative] = tc.sha256(str(ROOT / relative))
    key = hashlib.sha256((train_sha + "|0" + "".join(feature_hashes.values())).encode()).hexdigest()[:16]
    cache = Path(cache_dir) / f"v2feat_{key}.pkl"
    return {"code_sha256": code, "python": platform.python_version(),
            "packages": {name: importlib.metadata.version(name) for name in ("numpy", "scipy", "scikit-learn", "threadpoolctl")},
            "feature_cache": {"file": cache.name, "sha256": tc.sha256(str(cache)),
                              "limitation": "Reused legacy cache; its key omits train_classic_v2.py. "
                                            "Current trainer and feature-loop hashes are recorded separately."}}


def split_indices(rows: list[dict]) -> dict[str, np.ndarray]:
    """Keep repositories connected by conservative formatting duplicates together."""
    parent = {row["group"]: row["group"] for row in rows}
    def find(group):
        while parent[group] != group:
            parent[group] = parent[parent[group]]
            group = parent[group]
        return group
    owners = {}
    for row in rows:
        keys = [("norm", row.get("norm_hash"))]
        if not is_trivial(row["code"]):
            keys.append(("compact", hashlib.sha256(re.sub(r"\s+", "", row["code"]).encode()).hexdigest()))
        for kind, digest in keys:
            if not digest:
                continue
            key = (kind, digest)
            if key in owners:
                a, b = sorted((find(row["group"]), find(owners[key])))
                parent[b] = a
            owners[key] = row["group"]
    for row in rows:
        row["_experiment_group"] = find(row["group"])
    grouped = [dict(row, group=row["_experiment_group"]) for row in rows]
    folds = [te for _, te in ec.group_folds(grouped, 5, SEED)]
    result = {"fit": np.concatenate(folds[:2]), "calibration": folds[2],
              "selection": folds[3], "validation": folds[4]}
    seen = set()
    for indices in result.values():
        groups = {rows[i]["_experiment_group"] for i in indices}
        if seen & groups:
            raise ValueError("repository groups overlap across split")
        seen |= groups
    return result


def measures(rows, scores, thresholds):
    masks = ec._masks(rows)
    return {level: {"real_recall": ec.rate(scores >= threshold, masks["real_pos_noninfo"]),
                    "corpus_false_alarm": ec.rate(scores >= threshold, masks["corpus_contract"]),
                    "fixed_false_alarm": ec.rate(scores >= threshold, masks["paired_fixed"]),
                    "mutation_recall": ec.rate(scores >= threshold, masks["mutation"])}
            for level, threshold in thresholds.items()}


def select_candidate(metrics):
    baseline = metrics["baseline"]
    selected = "baseline"
    def key(m):
        return (m["block"]["real_recall"]["rate"], m["warn"]["real_recall"]["rate"],
                -m["block"]["fixed_false_alarm"]["rate"])
    for name, m in metrics.items():
        eligible = (m["block"]["corpus_false_alarm"]["rate"] <= 0.02
                    and m["warn"]["corpus_false_alarm"]["rate"] <= 0.075
                    and m["block"]["fixed_false_alarm"]["rate"]
                    <= baseline["block"]["fixed_false_alarm"]["rate"] + 0.05)
        if eligible and key(m) > key(metrics[selected]):
            selected = name
    return selected


def paired_group_ci(rows, base_hit, candidate_hit, repetitions=2000):
    """Resample groups containing real positives; keep paired decisions for both models."""
    mask = ec._masks(rows)["real_pos_noninfo"]
    group_ids = [r.get("_experiment_group", r["group"]) for r in rows]
    groups = sorted({group_ids[i] for i in range(len(rows)) if mask[i]})
    counts = np.array([[sum(mask[i] and group_ids[i] == group for i in range(len(rows))),
                        sum((int(candidate_hit[i]) - int(base_hit[i])) for i, r in enumerate(rows)
                            if mask[i] and group_ids[i] == group)] for group in groups])
    if not groups:
        return {"groups": 0, "ci95": [None, None]}
    rng = np.random.RandomState(SEED)
    samples = counts[rng.randint(len(groups), size=(repetitions, len(groups)))].sum(axis=1)
    deltas = samples[:, 1] / samples[:, 0]
    return {"groups": len(groups), "repetitions": repetitions,
            "group_counts": [{"component": group, "real_positive_n": int(counts[i, 0]),
                              "candidate_minus_baseline_hits": int(counts[i, 1])} for i, group in enumerate(groups)],
            "ci95": np.quantile(deltas, [0.025, 0.975]).tolist()}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cache-dir", help="Existing hash-keyed v2 feature cache, or a new cache directory")
    ap.add_argument("--output-dir", type=Path, help="Write a fresh report, artifact and optional feature cache here")
    args = ap.parse_args()
    os.chdir(ROOT)
    report_path = args.output_dir / REPORT.name if args.output_dir else REPORT
    artifact_path = args.output_dir / ARTIFACT.name if args.output_dir else ARTIFACT
    if report_path.exists() or artifact_path.exists():
        raise SystemExit("experiment output exists; preserve it and choose a fresh --output-dir")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    report = {"status": "declared_before_fitting", "protocol": PROTOCOL, "protocol_sha256": sha(PROTOCOL),
              "run_trainer_sha256": tc.sha256(str(Path(__file__)))}
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    rows, info = tc.load_train(str(TRAIN))
    splits = split_indices(rows)
    report["dataset"] = info
    report["feature_code_sha256"] = {str(path.relative_to(ROOT)): tc.sha256(str(path)) for path in (
        ROOT / "near/model/context.py", ROOT / "near/model/featurize.py", ROOT / "near/analyzer/detectors.py",
        ROOT / "near/analyzer/features.py", ROOT / "near/analyzer/rust_parse.py")}
    report["split_audit"] = {name: {"n": len(idx), "groups": len({rows[i]["group"] for i in idx}),
        "merged_components": len({rows[i]["_experiment_group"] for i in idx}),
        "group_names": sorted({rows[i]["group"] for i in idx}),
        "ids_sha256": sha(sorted(rows[i]["id"] for i in idx)),
        "real_positive": sum(ec.is_real(rows[i]) and rows[i]["label"] == 1 for i in idx)}
        for name, idx in splits.items()}
    tc.CACHE_DIR = args.cache_dir or str((args.output_dir or ROOT / "near/models") / "code_candidate_features")
    matrix = tc.with_derived(tc.featurize(rows, workers=3, cache_key=info["train_sha256"] + "|0"))
    report["provenance"] = provenance(report["feature_code_sha256"], info["train_sha256"], tc.CACHE_DIR)
    matrix = {key: matrix[key] for key in ("A1", "D", "Xn", "T")}
    eligible = np.array([not is_trivial(row["code"]) for row in rows])
    fit = splits["fit"][eligible[splits["fit"]]]
    fit_rows = [rows[i] for i in fit]
    y = np.array([row["label"] for row in rows])
    models, scores, thresholds, selection = {}, {}, {}, {}
    with threadpool_limits(4):
        for name, params in CANDIDATES.items():
            tick = time.time()
            model = tc.fit_model(params, tc.BLOCKS["v2_noera"], tc._sub(matrix, fit), y[fit],
                                 tc.weights(fit_rows, params), SEED)
            models[name] = model
            scores[name] = {}
            for part in ("calibration", "selection"):
                idx = splits[part]
                pred = tc.predict_model(model, tc._sub(matrix, idx))
                pred[~eligible[idx]] = 0.0
                scores[name][part] = pred
            thresholds[name] = ec.thresholds_from([rows[i] for i in splits["calibration"]], scores[name]["calibration"])
            selection[name] = measures([rows[i] for i in splits["selection"]], scores[name]["selection"], thresholds[name])
            print(f"{name}: selection high recall={selection[name]['block']['real_recall']['rate']:.3f}, "
                  f"high FPR={selection[name]['block']['corpus_false_alarm']['rate']:.3f}; {time.time()-tick:.1f}s", flush=True)
        chosen = select_candidate(selection)
        report.update(selected=chosen, selection=selection, thresholds=thresholds)
        report_path.write_text(json.dumps(report, indent=2) + "\n")  # freeze choice before final validation
        validation = {}
        idx = splits["validation"]
        validation_rows = [rows[i] for i in idx]
        for name in dict.fromkeys(("baseline", chosen)):
            pred = tc.predict_model(models[name], tc._sub(matrix, idx))
            pred[~eligible[idx]] = 0.0
            scores[name]["validation"] = pred
            validation[name] = measures(validation_rows, pred, thresholds[name])
    base, candidate = validation["baseline"], validation[chosen]
    ci = paired_group_ci(validation_rows, scores["baseline"]["validation"] >= thresholds["baseline"]["block"],
                         scores[chosen]["validation"] >= thresholds[chosen]["block"])
    checks = {
        "different_candidate": chosen != "baseline",
        "real_high_gain_at_least_3pp": candidate["block"]["real_recall"]["rate"] >= base["block"]["real_recall"]["rate"] + .03,
        "positive_group_bootstrap_lower_bound": ci["ci95"][0] is not None and ci["ci95"][0] > 0,
        "no_medium_recall_loss": candidate["warn"]["real_recall"]["rate"] >= base["warn"]["real_recall"]["rate"],
        "high_false_alarm_budget": candidate["block"]["corpus_false_alarm"]["rate"] <= max(.015, base["block"]["corpus_false_alarm"]["rate"] + .002),
        "medium_false_alarm_budget": candidate["warn"]["corpus_false_alarm"]["rate"] <= max(.06, base["warn"]["corpus_false_alarm"]["rate"] + .005),
        "fixed_false_alarm_budget": candidate["block"]["fixed_false_alarm"]["rate"] <= base["block"]["fixed_false_alarm"]["rate"] + .03,
    }
    report.update(status="completed", validation=validation, real_high_gain_group_bootstrap=ci,
                  adoption_checks=checks, recommendation="candidate_for_fresh_evaluation" if all(checks.values()) else "retain_current_model",
                  duration_seconds=round(time.time()-started, 2),
                  limitation="Training-only development split, not an independent sealed benchmark; no production artifact changed.")
    artifact = {"model": models[chosen], "thresholds": thresholds[chosen], "candidate": chosen,
                "train_sha256": info["train_sha256"], "protocol_sha256": sha(PROTOCOL), "research_only": True}
    artifact["inference"] = {"features": "near.model.train_classic_v2.matrices_for_source(files, fns)",
                             "predict": "near.model.train_classic_v2.predict_model(model, matrices)",
                             "trivial_functions": "force probability to 0; use near.collect.extract_corpus.is_trivial",
                             "feature_code_sha256": report["feature_code_sha256"]}
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(pickle.dumps(artifact, protocol=pickle.HIGHEST_PROTOCOL))
    report["artifact_sha256"] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    report_path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"selected": chosen, "recommendation": report["recommendation"], "adoption_checks": checks,
                      "duration_seconds": report["duration_seconds"]}), flush=True)


if __name__ == "__main__":
    main()
