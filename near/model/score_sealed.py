"""Score the sealed test (near/data/test_v1.jsonl) ONCE with the frozen model and its frozen thresholds.

Refuses to run if the report already exists, if any frozen hash changed (pickle, feature code, train rows, train ids,
split manifest, test file vs manifest), if the feature schema differs, or if test ids / groups / norm_hashes overlap
train. Test rows go through the training featurization (featurize.fill_context + featurize_rows), exactly like train.

    uv run python -m near.model.score_sealed     # writes reports/sealed_test_v1.{json,md}, appends reports/RESULTS.md
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
from collections import Counter, defaultdict

import numpy as np

from near.analyzer.features import FEATURE_KEYS
from near.model import eval_common as ec
from near.model import featurize as fz
from near.model import freeze, predict
from near.model import train_classic as tc

TEST = "near/data/test_v1.jsonl"
REPORTS = "near/model/reports"
OUT = f"{REPORTS}/sealed_test_v1"
CONFLICTS = "near/data/split_audit_scratch/label_conflicts_j09.json"
TIME_SPLIT = "2025-01-01"


def check_disjoint(train: list[dict], test: list[dict]) -> list[str]:
    probs = []
    for key in ("id", "group", "norm_hash"):
        shared = {r[key] for r in train if r.get(key)} & {r[key] for r in test if r.get(key)}
        if shared:
            probs.append(f"{len(shared)} shared {key} values between train and test, e.g. {sorted(shared)[:3]}")
    return probs


def check_frozen(man: dict, train: list[dict], test_path: str) -> list[str]:
    probs = []
    if freeze.rows_sha256(train) != man["train_rows_sha256"]:
        probs.append("train rows (id, label) differ from the frozen ones")
    if predict.sha256_file(man["train_ids_file"]) != man["train_ids_sha256"]:
        probs.append("train ids file changed")
    elif set(freeze.read_json(man["train_ids_file"])) != {r["id"] for r in train}:
        probs.append("train ids file does not match the train rows")
    if predict.sha256_file(man["split_manifest"]) != man["split_manifest_sha256"]:
        probs.append("split manifest changed")
    else:
        want = freeze.read_json(man["split_manifest"])["files"][os.path.basename(test_path)]["sha256"]
        if predict.sha256_file(test_path) != want:
            probs.append(f"{test_path} sha256 differs from the split manifest")
    fs = man["feature_schema"]
    if fs["analyzer_keys"] != list(FEATURE_KEYS) or fs["token_dim"] != fz.TOKEN_DIM or fs["token_hash"] != freeze.token_hash_spec():
        probs.append("feature schema differs from the frozen one")
    if predict.code_hashes() != man["code_sha256"]:
        probs.append("feature code changed")
    return probs


def in_time_split(r: dict) -> bool:
    return ec.is_real(r) and r["label"] == 1 and bool(r.get("date")) and r["date"] >= TIME_SPLIT


def rates_by(rows: list[dict], hit: np.ndarray, mask: np.ndarray, key) -> dict:
    keys = np.array([str(key(r)) for r in rows], object)
    return {k: ec.rate(hit, mask & (keys == k)) for k in sorted(set(keys[mask]))}


def incident_outcomes(rows: list[dict], scores: np.ndarray, thr: dict) -> list[dict]:
    """Per held-out incident (rows of source incident, named by `finding`): best level reached by any of its
    vulnerable functions, and by its fixed versions (label 0) for contrast."""
    def level(s):
        return "block" if s >= thr["block"] else "warn" if s >= thr["warn"] else "missed"
    inc = defaultdict(lambda: {"vuln": [], "fixed": []})
    for r, s in zip(rows, scores):
        if r["source"] == "incident":
            d = inc[r.get("finding") or r.get("evidence") or r["group"]]
            d["vuln" if r["label"] == 1 else "fixed"].append((float(s), r))
    out = []
    for name, d in sorted(inc.items()):
        if not d["vuln"]:
            continue
        best, r = max(d["vuln"], key=lambda t: t[0])
        fixed = max((s for s, _ in d["fixed"]), default=None)
        out.append({"incident": name, "group": r["group"], "date": r.get("date"), "vuln_class": r.get("vuln_class"),
                    "evidence": r.get("evidence"), "n_vulnerable_fns": len(d["vuln"]), "max_risk": round(best, 4),
                    "outcome": level(best), "riskiest_fn": r.get("fn"),
                    "fixed_version_alarm": None if fixed is None else level(fixed)})
    return out


def score(rows: list[dict], art: dict, workers: int) -> tuple[np.ndarray, list]:
    """Frozen-model scores; trivial functions get -1 (never alarm, as in near.model.predict) and no class guess."""
    fz.fill_context(rows)
    A, T, _ = tc.featurize_rows(rows, workers)
    s = tc.predict_model(art["estimator"], A, T, None)
    guess, _ = predict.class_guess(art["class_head"], A, T)
    triv = np.array([not predict.model_scored(r) for r in rows])
    s[triv] = -1.0
    return s, [None if t else g for t, g in zip(triv, guess)]


def report(rows: list[dict], s: np.ndarray, guess: list[str], thr: dict, conflicts: set) -> dict:
    hit = {lvl: s >= t for lvl, t in thr.items()}
    m = ec.metrics(rows, s, hit)
    real_pos = np.array([ec.is_real(r) and r["label"] == 1 for r in rows])
    noninfo = real_pos & np.array([r.get("severity") != "info" for r in rows])
    ts = np.array([in_time_split(r) for r in rows])
    mut = np.array([r["source"] == "mutation" and r["label"] == 1 for r in rows])
    fixed = np.array([ec.is_real(r) and r["label"] == 0 for r in rows])
    conf = np.array([r["id"] in conflicts for r in rows])
    cc = np.array([r["source"] == "corpus" and r["label"] == 0 and ec.is_contract_code(r) for r in rows])
    out = {"overall": {k: m[k] for k in ("n", "n_pos", "pr_auc", "roc_auc", "pr_auc_weighted",
                                          "roc_auc_real_vs_contract_corpus", "roc_auc_mutation_vs_contract_corpus",
                                          "roc_auc_real_vs_fixed", "pair_rank_acc")}}
    for lvl, h in hit.items():
        x = m[lvl]
        out[lvl] = {
            "threshold": thr[lvl], "recall_real": x["recall_real"], "recall_real_noninfo": x["recall_real_noninfo"],
            "recall_real_info": x["recall_real_info"],
            "recall_real_by_source": rates_by(rows, h, real_pos, lambda r: r["source"]),
            "recall_real_noninfo_by_source": rates_by(rows, h, noninfo, lambda r: r["source"]),
            "recall_real_by_class": rates_by(rows, h, real_pos, lambda r: r.get("vuln_class")),
            "recall_real_by_severity": rates_by(rows, h, real_pos, lambda r: r.get("severity")),
            "time_split_recall_real": ec.rate(h, ts), "time_split_recall_real_noninfo": ec.rate(h, ts & noninfo),
            "time_split_by_source": rates_by(rows, h, ts, lambda r: r["source"]),
            "time_split_by_class": rates_by(rows, h, ts, lambda r: r.get("vuln_class")),
            "time_split_by_severity": rates_by(rows, h, ts, lambda r: r.get("severity")),
            "recall_mutation": x["recall_mutation"], "recall_mutation_by_class": x["recall_class_mutation"],
            "fpr_corpus": x["fpr_corpus"], "fpr_corpus_contract": x["fpr_corpus_contract"],
            "fpr_corpus_contract_excl_label_conflicts": ec.rate(h, cc & ~conf),
            "fpr_paired_fixed": x["fpr_paired_fixed"], "fpr_paired_fixed_excl_label_conflicts": ec.rate(h, fixed & ~conf),
            "fpr_mutation_original": x["fpr_mutation_original"],
            "contract_level_protocol_rule": {"clean_files": x["contract_alarm_share"],
                                             "real_vuln_files": x["contract_recall_real"]},
            "contract_level_deployed_rule": freeze.contract_level(rows, h),
            "contract_level_deployed_rule_by_file": freeze.contract_level(rows, h, clean_by="file"),
        }
    out["incidents"] = incident_outcomes(rows, s, thr)
    ev = real_pos & np.array([bool(r.get("vuln_class")) for r in rows])
    yt = np.array([r.get("vuln_class") or "" for r in rows], object)
    g = np.array([x or "" for x in guess], object)
    out["class_head"] = {"n": int(ev.sum()), "accuracy": float((g[ev] == yt[ev]).mean()) if ev.any() else None,
                         "macro_f1": _macro_f1(yt[ev], g[ev])}
    out["label_conflict_rows_in_test"] = int(conf.sum())
    triv = s == -1.0
    out["trivial_rows_not_scored"] = dict(Counter(f"{r['source']}|{r['label']}" for r, t in zip(rows, triv) if t))
    return out


def _macro_f1(y, p) -> float | None:
    from sklearn.metrics import f1_score
    return float(f1_score(y, p, labels=sorted(set(y)), average="macro", zero_division=0)) if len(y) else None


def render_md(rep: dict) -> str:
    o, b, w = rep["overall"], rep["block"], rep["warn"]
    f = ec.fmt_rate
    out = [f"# Sealed test v1: frozen NEAR code-risk model, scored once ({rep['scored_at']})", "",
           f"Model `{rep['model']['version']}` sha256 `{rep['model']['sha256'][:16]}...` ({rep['model_name']}), "
           f"thresholds block {b['threshold']:.4f} / warn {w['threshold']:.4f} (frozen, from train OOF). Test "
           f"`{rep['test_file']}` sha256 `{rep['test_sha256'][:16]}...`: {o['n']} rows, {o['n_pos']} label-1, "
           f"{rep['n_groups']} groups. Rows by source/label: {rep['counts']}. Checks passed before scoring: hashes, "
           "feature schema, no shared id / group / norm_hash with train.", "",
           f"PR-AUC {o['pr_auc']:.3f} (weighted {o['pr_auc_weighted']:.3f}), ROC-AUC {o['roc_auc']:.3f}; ROC-AUC real "
           f"label-1 vs contract-code corpus {o['roc_auc_real_vs_contract_corpus']:.3f}, mutations vs contract corpus "
           f"{o['roc_auc_mutation_vs_contract_corpus']:.3f}, real vs paired fixed {o['roc_auc_real_vs_fixed']:.3f}; "
           f"pair rank (vulnerable > fixed) {f(o['pair_rank_acc'])}.", "",
           "| | block | warn |", "|---|---|---|"]
    rows = [("recall, real label-1 (all)", "recall_real"), ("recall, real label-1 severity != info", "recall_real_noninfo"),
            ("recall, real label-1 severity = info", "recall_real_info"),
            ("time split (real label-1 dated >= 2025): recall", "time_split_recall_real"),
            ("time split: recall, severity != info", "time_split_recall_real_noninfo"),
            ("recall, mutations", "recall_mutation"), ("false alarms, corpus negatives (all)", "fpr_corpus"),
            ("false alarms, contract-code corpus negatives", "fpr_corpus_contract"),
            ("false alarms, contract-code corpus excl. label conflicts", "fpr_corpus_contract_excl_label_conflicts"),
            ("false alarms, paired fixed versions", "fpr_paired_fixed"),
            ("false alarms, paired fixed excl. label conflicts", "fpr_paired_fixed_excl_label_conflicts"),
            ("false alarms, mutation originals", "fpr_mutation_original")]
    out += [f"| {label} | {f(b[k])} | {f(w[k])} |" for label, k in rows]
    fl = "contract_level_deployed_rule_by_file"
    if fl in b:
        out.append(f"| contract level deployed rule: test corpus files holding no real label-1 alarming | "
                   f"{f(b[fl]['clean_files'])} | {f(w[fl]['clean_files'])} |")
    for rule in ("contract_level_deployed_rule", "contract_level_protocol_rule"):
        out += [f"| {rule.replace('_', ' ')}: clean files alarming | {f(b[rule]['clean_files'])} | "
                f"{f(w[rule]['clean_files'])} |",
                f"| {rule.replace('_', ' ')}: files holding a real vulnerability alarming | "
                f"{f(b[rule]['real_vuln_files'])} | {f(w[rule]['real_vuln_files'])} |"]
    for title, key in (("Real label-1 recall by source", "recall_real_by_source"),
                       ("Real label-1 (severity != info) recall by source", "recall_real_noninfo_by_source"),
                       ("Real label-1 recall by vuln_class", "recall_real_by_class"),
                       ("Real label-1 recall by severity", "recall_real_by_severity"),
                       ("Time split (>= 2025) recall by source", "time_split_by_source"),
                       ("Time split recall by vuln_class", "time_split_by_class"),
                       ("Time split recall by severity", "time_split_by_severity"),
                       ("Mutation recall by vuln_class", "recall_mutation_by_class")):
        out += ["", f"### {title}", "", "| | block | warn |", "|---|---|---|"]
        out += [f"| {k} | {f(v)} | {f(w[key][k])} |" for k, v in b[key].items()]
    out += ["", "### Held-out incidents (hacks)", "", "| incident | date | class | vulnerable fns | max risk | outcome | "
            "fixed version alarms at |", "|---|---|---|---|---|---|---|"]
    out += [f"| {i['incident']} | {i['date']} | {i['vuln_class']} | {i['n_vulnerable_fns']} | {i['max_risk']:.3f} | "
            f"**{i['outcome']}** | {i['fixed_version_alarm'] or 'n/a'} |" for i in rep["incidents"]]
    ch = rep["class_head"]
    out += ["", f"vuln_class head on {ch['n']} real label-1 rows: accuracy {ch['accuracy']:.3f}, macro-F1 "
            f"{ch['macro_f1']:.3f}.", "", "Label conflicts (split audit `label_conflicts_j09.json`, test label-0 rows "
            f"that are near-identical to a label-1 row): {rep['label_conflict_rows_in_test']} rows in test.", "",
            "Trivial functions (< 2 statements or body < 3 lines) are not scored by the deployed model and count as "
            f"not alarming: {rep['trivial_rows_not_scored']} test rows (source|label)."]
    return "\n".join(out) + "\n"


def results_entry(rep: dict) -> str:
    b, w, o, f = rep["block"], rep["warn"], rep["overall"], ec.fmt_rate
    inc = rep["incidents"]
    caught = {lvl: sum(i["outcome"] == lvl for i in inc) for lvl in ("block", "warn", "missed")}
    return "\n".join([
        f"## SEALED TEST v1 (NEAR code risk) — frozen `{rep['model']['version']}`, scored once {rep['scored_at']}",
        f"- Model: {rep['model_name']}; trained on {rep['train_rows']} train_v1 rows ({rep['train_positives']} label-1); "
        f"thresholds block {b['threshold']:.4f} / warn {w['threshold']:.4f} = 1% / 5% FPR on contract-code corpus "
        "functions in training OOF scores; chosen over avg(hgb,logreg) and the UniXcoder encoder by nested-CV block "
        "recall on real vulnerabilities.",
        f"- Test: {o['n']} functions from {rep['n_groups']} held-out repos; {o['n_pos']} label-1.",
        f"- **Real vulnerabilities (severity != info): block {f(b['recall_real_noninfo'])}, warn "
        f"{f(w['recall_real_noninfo'])}**; all real {f(b['recall_real'])} / {f(w['recall_real'])}",
        f"- Time split (real, dated >= 2025): block {f(b['time_split_recall_real'])}, warn "
        f"{f(w['time_split_recall_real'])}",
        f"- Mutations: block {f(b['recall_mutation'])}, warn {f(w['recall_mutation'])}",
        f"- False alarms, contract-code corpus functions: block {f(b['fpr_corpus_contract'])}, warn "
        f"{f(w['fpr_corpus_contract'])}; paired fixed versions: block {f(b['fpr_paired_fixed'])}, warn "
        f"{f(w['fpr_paired_fixed'])}",
        f"- Contract level (deployed rule): test corpus files holding no real label-1 alarm at block "
        f"{f(b['contract_level_deployed_rule_by_file']['clean_files'])}, warn "
        f"{f(w['contract_level_deployed_rule_by_file']['clean_files'])}; files holding a real label-1 alarm at block "
        f"{f(b['contract_level_deployed_rule']['real_vuln_files'])}, warn "
        f"{f(w['contract_level_deployed_rule']['real_vuln_files'])}",
        f"- Held-out hacks: {caught['block']} block, {caught['warn']} warn, {caught['missed']} missed of {len(inc)}",
        f"- PR-AUC {o['pr_auc']:.3f}, ROC-AUC {o['roc_auc']:.3f}, real vs fixed ROC-AUC {o['roc_auc_real_vs_fixed']:.3f}",
        f"- Details: near/model/reports/sealed_test_v1.md. After this scoring test_v1 is spent: the model is not "
        "changed on its basis; any later change needs a new sealed test.", ""])


def add_file_level(out: str, test_path: str) -> None:
    """Report-only fix after the one scoring: add the per-file clean-contract rate (every test group holds a real
    label-1 row, so the per-group rate is empty) from the saved scores; the model is not run again."""
    with open(test_path) as f:
        rows = [json.loads(line) for line in f]
    s = np.load(f"{out}_scores.npy")
    rep = freeze.read_json(f"{out}.json")
    for lvl in ec.LEVELS:
        rep[lvl]["contract_level_deployed_rule_by_file"] = tc._jsonable(
            freeze.contract_level(rows, s >= rep[lvl]["threshold"], clean_by="file"))
    rep["file_level_added_from_saved_scores"] = datetime.date.today().isoformat()
    freeze.write_json(f"{out}.json", rep)
    with open(f"{out}.md", "w") as f:
        f.write(render_md(rep))
    print(results_entry(rep))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--test", default=TEST)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--add-file-level", action="store_true", help="report-only: per-file clean rate from saved scores")
    args = ap.parse_args()
    if args.add_file_level:
        return add_file_level(args.out, args.test)
    if os.path.exists(f"{args.out}.json") or os.path.exists(f"{args.out}.started"):
        raise SystemExit(f"{args.out}.json (or .started) exists: the sealed test is scored once")
    art = predict.load()  # checks pickle sha256 and feature code against the manifest
    man = freeze.read_json(freeze.manifest_path(predict.FROZEN))
    train, _, _ = freeze.train_rows(man["train_subset"])
    probs = check_frozen(man, train, args.test)
    with open(args.test) as f:
        test = [json.loads(line) for line in f]
    probs += check_disjoint(tc.load_train(man["train_file"])[0], test)  # all train rows, not only the fitted ones
    if probs:
        raise SystemExit("refusing to score:\n  " + "\n  ".join(probs))
    open(f"{args.out}.started", "w").write(datetime.datetime.now(datetime.timezone.utc).isoformat() + "\n")

    s, guess = score(test, art, args.workers)
    conflicts = {c["label0_id"] for c in freeze.read_json(CONFLICTS)["test"]}
    rep = report(test, s, guess, art["thresholds"], conflicts)
    counts = defaultdict(int)
    for r in test:
        counts[f"{r['source']}|{r['label']}"] += 1
    rep.update(scored_at=datetime.date.today().isoformat(), model=art["info"], model_name=man["model_name"],
               train_rows=man["train_rows"], train_positives=man["train_positives"], test_file=args.test,
               test_sha256=predict.sha256_file(args.test), n_groups=len({r["group"] for r in test}),
               counts=dict(sorted(counts.items())),
               context_from={k: sum(r.get("context_from") == k for r in test) for k in ("row", "repo", "code")})
    freeze.write_json(f"{args.out}.json", tc._jsonable(rep))
    np.save(f"{args.out}_scores.npy", s)
    with open(f"{args.out}.md", "w") as f:
        f.write(render_md(rep))
    res = f"{REPORTS}/RESULTS.md"
    head = "" if os.path.exists(res) else "# NEAR results log (sealed tests are scored once, numbers recorded as-is)\n\n"
    with open(res, "a") as f:
        f.write(head + results_entry(rep) + "\n")
    print(render_md(rep))


if __name__ == "__main__":
    main()
