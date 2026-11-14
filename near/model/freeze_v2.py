"""Freeze the v2 NEAR code-risk model, in three stages that run in this order and leave a trail:

1. `decide`: picks classical v2, the code LLM or their ensemble from nested-CV numbers on train_v2 only, by a rule
   fixed in this file (DECISION_RULE), and writes near/models/frozen_near_v2.decision.{json,md}. It runs before any
   test file is read; the scoring stage records the decision's sha256 and refuses to run without it.
2. `freeze`: refits the chosen model on all usable train_v2 rows, takes block / warn thresholds from grouped OOF
   scores (1% / 5% FPR on contract-code corpus negatives), writes near/models/frozen_near_v2.{pkl,json} and the train
   ids, and checks that the reloaded artifact and near.model.predict's inference path give the training scores.
3. `score`: scores near/data/test_v1c.jsonl once with v2 and with the frozen v1 model (same cleaned labels), and v1 /
   v2 on the original test_v1 labels for continuity. test_v1c is DEVELOPMENT-INFORMED, not sealed: test_v1's aggregate
   v1 results were seen before v2 was designed, and its labels were cleaned after that (blind to predictions).

    uv run python -m near.model.freeze_v2 decide   # about 1 min (featurizes train_v2 for the no-file mask); once
    uv run python -m near.model.freeze_v2 freeze   # about 6 min (MPS for the LLM's held-out scores)
    uv run python -m near.model.freeze_v2 score    # about 4 min; once; writes near/model/reports/test_v1c_v2.{json,md}

The decide stage picked the ensemble (frozen_near_v2.decision.md), so `freeze` implements the ensemble only.

Set NEAR_V2_CACHE=<dir> to reuse train_classic_v2's feature cache between stages.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import time
from collections import Counter

import numpy as np
from scipy.stats import rankdata

from near.collect.extract_corpus import is_trivial
from near.model import eval_common as ec
from near.model import freeze
from near.model import train_classic_v2 as tc2

OUT = "near/models"
TAG = "frozen_near_v2"
DECISION = f"{OUT}/{TAG}.decision"
TRAIN = "near/data/train_v2.jsonl"
CLASSIC_V2 = "near/model/reports/classic_v2_cv"
CLASSIC_PICK = "ctx_fixed_noera"  # train_classic_v2's protocol pick (pre-declared key, nested CV)
LLM_OOF = "near/models/llm_oof.jsonl"
LLM_CV_DIR = "near/models/llm_qwen05_cv3"
LLM_LATENCY = "near/models/llm_qwen05_final/latency.json"
BLOCK_KEYS = ("A0", "A1", "D", "X", "T")
SPLIT_MANIFEST_V2 = "near/data/split_manifest_v2.json"
CLEAN_FILE_MAX = 0.05
DECISION_RULE = (
    "Candidates: classical v2 (train_classic_v2 protocol pick ctx_fixed_noera), the code LLM (Qwen2.5-Coder-0.5B "
    "LoRA, llm_classifier qwen05_cv3) and their mean-rank ensemble, compared on the same train_v2 rows (the 47 rows "
    "without their source file and trivial functions excluded, as deployed) from their out-of-fold scores. "
    "(0) Eligible: share of clean contract files (corpus files of groups with no real vulnerability) alarming at "
    "block <= 5%. (1) Primary: block recall on real vulnerabilities whose relabel verdict is `confirmed`, all models "
    "at pooled thresholds (exactly 1% contract-corpus FPR each, so they are compared at the same false-alarm rate; "
    "the ensemble has no nested thresholds). A challenger replaces classical v2 only if the bootstrap-over-groups 95% "
    "interval of its gain excludes 0. (2) Secondary, if (1) decides nothing: pair ranking on the real (vulnerable, "
    "fixed) pairs whose vulnerable version is not shorter than its fix (raw pair rank is gamed by length: fixes add "
    "code); a challenger wins only if its interval lies above 50% and its gain over classical v2 excludes 0. "
    "(3) Otherwise latency: the cheaper model, classical v2.")


def read_json(path):
    with open(path) as f:
        return json.load(f)


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# --- train rows and features ------------------------------------------------------------------------------------
def load_train_features(workers: int) -> tuple[list[dict], np.ndarray, list[dict], dict, dict]:
    """train_classic_v2's rows and matrices: (rows with their file, non-trivial mask over them, non-trivial rows,
    their v2 blocks incl. Xn, info with the excluded no-file ids)."""
    rows_all, info = tc2.load_train(TRAIN)
    M_all = tc2.featurize(rows_all, workers, cache_key=f"{info['train_sha256']}|0")
    nf = ~M_all["available"]
    info["no_file_ids"] = sorted(r["id"] for r, x in zip(rows_all, nf) if x)
    info["no_file_by"] = dict(Counter(f"{r['source']}:{r['label']}" for r, x in zip(rows_all, nf) if x))
    rows_all = [r for r, x in zip(rows_all, nf) if not x]
    scored = np.array([not is_trivial(r["code"]) for r in rows_all])
    idx = np.where(scored)[0]
    M = tc2.with_derived({k: M_all[k][~nf][idx] for k in BLOCK_KEYS})
    return rows_all, scored, [rows_all[i] for i in idx], M, info


# --- stage 1: decision --------------------------------------------------------------------------------------------
def classic_oof(rows_all: list[dict], scored: np.ndarray, name: str) -> tuple[np.ndarray, dict]:
    """Saved nested OOF scores of a train_classic_v2 candidate and its nested decisions (per outer fold
    thresholds), over rows_all (trivial rows -1, never alarming)."""
    rep = read_json(f"{CLASSIC_V2}.json")
    s = np.load(f"{CLASSIC_V2}_{name}_oof.npy")
    if len(s) != len(rows_all):
        raise SystemExit(f"{name} OOF has {len(s)} rows, expected {len(rows_all)}")
    idx = np.where(scored)[0]
    fold_of = np.full(len(rows_all), -1)
    for k, (_, te) in enumerate(ec.group_folds([rows_all[i] for i in idx], 5, ec.SEED)):
        fold_of[idx[te]] = k
    thr = rep["candidates"][name]["fold_thresholds"]
    return s, {lvl: scored & (s >= np.array([np.inf if t is None else t for t in thr[lvl]])[fold_of])
               for lvl in ec.LEVELS}


def llm_oof(rows_all: list[dict], scored: np.ndarray) -> tuple[np.ndarray, dict]:
    """The LLM's pooled outer-fold scores and nested decisions (each fold's validation thresholds); trivial rows
    set to -1 as in the deployed rule."""
    by_id = {}
    with open(LLM_OOF) as f:
        for line in f:
            d = json.loads(line)
            by_id[d["id"]] = (d["score"], d["fold"])
    thr = {k: read_json(f"{LLM_CV_DIR}/fold{k}/fold.json")["thresholds"] for k in {f for _, f in by_id.values()}}
    s = np.array([by_id[r["id"]][0] for r in rows_all])
    fold = np.array([by_id[r["id"]][1] for r in rows_all])
    s[~scored] = -1.0
    return s, {lvl: scored & (s >= np.array([thr[k][lvl] for k in fold])) for lvl in ec.LEVELS}


def mean_rank(a: np.ndarray, b: np.ndarray, scored: np.ndarray) -> np.ndarray:
    s = np.full(len(a), -1.0)
    s[scored] = (rankdata(a[scored]) + rankdata(b[scored])) / (2 * scored.sum())
    return s


def is_confirmed(r: dict) -> bool:
    return ec.is_real(r) and r["label"] == 1 and r.get("relabel_verdict") == "confirmed"


def real_pairs(rows: list[dict], not_shorter: bool | None = None) -> tuple[np.ndarray, np.ndarray]:
    """Index arrays (vulnerable, fixed) of real pairs; not_shorter=True keeps pairs whose vulnerable code is not
    shorter (characters) than its fix, the subset where 'shorter = riskier' cannot help."""
    pos = {r["id"]: i for i, r in enumerate(rows)}
    pi, pj = [], []
    for i, r in enumerate(rows):
        j = pos.get(r.get("pair_id"))
        if ec.is_real(r) and r["label"] == 1 and j is not None and rows[j]["label"] == 0:
            if not_shorter is None or (len(r["code"]) >= len(rows[j]["code"])) == not_shorter:
                pi.append(i)
                pj.append(j)
    return np.array(pi, int), np.array(pj, int)


def pair_wins(s: np.ndarray, pi: np.ndarray, pj: np.ndarray) -> np.ndarray:
    return np.where(s[pi] > s[pj], 1.0, np.where(s[pi] == s[pj], 0.5, 0.0))


def rate_of(wins: np.ndarray) -> dict:
    k, n = float(wins.sum()), len(wins)
    lo, hi = ec.wilson(k, n)
    return {"k": k, "n": n, "rate": k / n if n else float("nan"), "lo": lo, "hi": hi}


def boot_diff(rows: list[dict], num_a: np.ndarray, num_b: np.ndarray, members: np.ndarray, n_boot: int = 2000,
              seed: int = ec.SEED) -> dict:
    """b minus a of a mean over `members` (row indices; values num_a / num_b per member), 95% interval from a
    bootstrap over groups."""
    groups = sorted({r["group"] for r in rows})
    gi = {g: i for i, g in enumerate(groups)}
    g = np.array([gi[rows[i]["group"]] for i in members], int)
    num = np.bincount(g, num_b - num_a, len(groups))
    den = np.bincount(g, minlength=len(groups)).astype(float)
    boot = np.random.RandomState(seed).randint(0, len(groups), (n_boot, len(groups)))
    bs = num[boot].sum(1) / np.maximum(den[boot].sum(1), 1)
    return {"diff": float(num.sum() / max(den.sum(), 1)), "lo": float(np.percentile(bs, 2.5)),
            "hi": float(np.percentile(bs, 97.5)), "n": int(den.sum())}


def summarize(rows: list[dict], s: np.ndarray, dec: dict | None) -> dict:
    """Decision numbers for one model; dec None = pooled thresholds only."""
    conf = np.array([is_confirmed(r) for r in rows])
    real_pos = np.array([ec.is_real(r) and r["label"] == 1 for r in rows])
    m = ec.metrics(rows, s, dec)
    pooled = {lvl: s >= t for lvl, t in ec.thresholds_from(rows, s).items()}
    out = {"pr_auc": m["pr_auc"], "roc_auc_real_vs_contract_corpus": m["roc_auc_real_vs_contract_corpus"],
           "roc_auc_real_vs_fixed": m["roc_auc_real_vs_fixed"], "pooled_thresholds": m["pooled_thresholds"],
           "pair_rank_real": rate_of(pair_wins(s, *real_pairs(rows))),
           "pair_rank_real_vuln_not_shorter": rate_of(pair_wins(s, *real_pairs(rows, True))),
           "pair_rank_real_vuln_shorter": rate_of(pair_wins(s, *real_pairs(rows, False)))}
    for kind, d in (("nested", dec), ("pooled", pooled)):
        if d is None:
            continue
        mm = m if kind == "nested" else ec.metrics(rows, s, pooled)
        out[kind] = {lvl: {"recall_confirmed": ec.rate(d[lvl], conf), "recall_real": ec.rate(d[lvl], real_pos),
                           "recall_mutation": mm[lvl]["recall_mutation"],
                           "fpr_corpus_contract": mm[lvl]["fpr_corpus_contract"],
                           "clean_file_alarm_share": mm[lvl]["contract_alarm_share"],
                           "clean_file_alarm_share_deployed_rule": freeze.contract_level(rows, d[lvl])["clean_files"],
                           "real_vuln_files_alarming": freeze.contract_level(rows, d[lvl])["real_vuln_files"]}
                      for lvl in ec.LEVELS}
    return out


def choose(summary: dict, diffs: dict) -> tuple[str, list[str]]:
    """DECISION_RULE applied to the numbers; returns (model, reasons)."""
    why = []
    eligible = []
    for name, x in summary.items():
        share = x.get("nested", x["pooled"])["block"]["clean_file_alarm_share"]["rate"]
        ok = share <= CLEAN_FILE_MAX
        why.append(f"(0) {name}: clean contract files alarming at block {100 * share:.1f}% -> "
                   f"{'eligible' if ok else 'not eligible'}")
        if ok:
            eligible.append(name)
    if "classical_v2" not in eligible:
        raise SystemExit("classical v2 is not eligible: the rule does not cover this case, decide by hand")
    winners = [n for n in eligible if n != "classical_v2" and diffs[n]["block_confirmed_pooled"]["lo"] > 0]
    for n in eligible:
        if n != "classical_v2":
            d = diffs[n]["block_confirmed_pooled"]
            why.append(f"(1) {n} - classical_v2, block recall on confirmed (pooled): {100 * d['diff']:+.1f} pts "
                       f"[{100 * d['lo']:+.1f}, {100 * d['hi']:+.1f}]")
    if winners:
        best = max(winners, key=lambda n: diffs[n]["block_confirmed_pooled"]["diff"])
        return best, why + [f"-> {best}: significant primary gain"]
    winners = [n for n in eligible if n != "classical_v2"
               and summary[n]["pair_rank_real_vuln_not_shorter"]["lo"] > 0.5
               and diffs[n]["pair_rank_not_shorter"]["lo"] > 0]
    for n in eligible:
        if n != "classical_v2":
            p, d = summary[n]["pair_rank_real_vuln_not_shorter"], diffs[n]["pair_rank_not_shorter"]
            why.append(f"(2) {n}: pair rank, vulnerable not shorter {ec.fmt_rate(p)}; gain over classical_v2 "
                       f"{100 * d['diff']:+.1f} pts [{100 * d['lo']:+.1f}, {100 * d['hi']:+.1f}]")
    if winners:
        best = max(winners, key=lambda n: diffs[n]["pair_rank_not_shorter"]["diff"])
        return best, why + [f"-> {best}: no primary difference, significant length-controlled pair-rank gain"]
    return "classical_v2", why + ["-> classical_v2: no significant difference on (1) or (2); it is the cheaper model (3)"]


def big_contract(rows: list[dict]) -> tuple[str, dict[str, str]]:
    """The largest source tree at HEAD (non-test .rs files plus Cargo.toml) among the train groups' local clones,
    by number of corpus rows: a large real NEAR contract repository for latency."""
    by = Counter(tc2.repo_dir(r) for r in rows if r["source"] == "corpus")
    by.pop(None, None)
    for d, _ in by.most_common(5):
        keys = tc2.cx.git_listing(d, "HEAD") or []
        want = [k for k in keys if (k.endswith(".rs") and not ec.TEST_PATH.search(k)
                                    and not ec.OFFCHAIN_PATH.search(k)) or k.endswith("Cargo.toml")]
        files = tc2.cx.git_read(d, "HEAD", want)
        if sum(k.endswith(".rs") for k in files) >= 10:
            return os.path.basename(d), files
    raise SystemExit("no local clone with a readable HEAD tree")


def classical_latency(files: dict[str, str]) -> dict:
    """Featurization time of the classical v2 inputs for a source tree (the HGB predict itself is ~ms)."""
    from near.analyzer import extract_functions
    t0 = time.time()
    fns = [f for p, src in sorted(files.items()) if p.endswith(".rs") for f in extract_functions(src, p)
           if not f.get("is_test")]
    t1 = time.time()
    keep = [f for f in fns if not is_trivial(f.get("code") or "")]
    tc2.matrices_for_source(files, keep)
    t2 = time.time()
    return {"n_files": sum(p.endswith(".rs") for p in files), "n_functions": len(fns), "n_model_scored": len(keep),
            "extract_s": round(t1 - t0, 2), "featurize_s": round(t2 - t1, 2)}


def decide(workers: int) -> None:
    if os.path.exists(f"{DECISION}.json"):
        raise SystemExit(f"{DECISION}.json exists: the decision is written once")
    t0 = time.time()
    rows_all, scored, _, _, info = load_train_features(workers)
    s_c, d_c = classic_oof(rows_all, scored, CLASSIC_PICK)
    s_v1, d_v1 = classic_oof(rows_all, scored, "v1_recipe")
    s_l, d_l = llm_oof(rows_all, scored)
    s_e = mean_rank(s_c, s_l, scored)
    models = {"classical_v2": (s_c, d_c), "llm_v2": (s_l, d_l), "ensemble_mean_rank": (s_e, None),
              "v1_recipe_on_train_v2 (reference, not a candidate)": (s_v1, d_v1)}
    summary = {n: summarize(rows_all, s, d) for n, (s, d) in models.items()}
    conf = np.where([is_confirmed(r) for r in rows_all])[0]
    pi, pj = real_pairs(rows_all, True)
    pooled = {n: s >= ec.thresholds_from(rows_all, s)["block"] for n, (s, _) in models.items()}
    diffs = {}
    for n, (s, d) in models.items():
        if n == "classical_v2":
            continue
        diffs[n] = {"block_confirmed_pooled": boot_diff(rows_all, pooled["classical_v2"][conf].astype(float),
                                                        pooled[n][conf].astype(float), conf),
                    "pair_rank_not_shorter": boot_diff(rows_all, pair_wins(s_c, pi, pj), pair_wins(s, pi, pj), pi)}
        if d is not None:
            diffs[n]["block_confirmed_nested"] = boot_diff(rows_all, d_c["block"][conf].astype(float),
                                                           d["block"][conf].astype(float), conf)
    cands = {n: summary[n] for n in ("classical_v2", "llm_v2", "ensemble_mean_rank")}
    choice, why = choose(cands, diffs)
    name, files = big_contract(rows_all)
    lat = {"classical_v2_big_contract": dict(classical_latency(files), repo=name),
           "llm_recorded_ms_per_fn": read_json(LLM_LATENCY)}
    n_fn = lat["classical_v2_big_contract"]["n_model_scored"]
    lat["llm_estimated_s_big_contract"] = {k: round(n_fn * v / 1000, 1) for k, v in lat["llm_recorded_ms_per_fn"].items()
                                           if k.endswith("_ms_per_fn") and k != "prep_ms_per_fn"}
    rep = {"written_at": utc_now(), "rule": DECISION_RULE, "choice": choice, "reasons": why,
           "classical_candidate": CLASSIC_PICK,
           "rows": {"train_file": TRAIN, "train_sha256": info["train_sha256"], "n_rows": len(rows_all),
                    "n_non_trivial": int(scored.sum()), "no_file_excluded": info["no_file_by"],
                    "n_confirmed": int(len(conf)), "n_real_pairs_not_shorter": int(len(pi))},
           "inputs": {p: tc2.sha256(p) for p in (f"{CLASSIC_V2}.json", f"{CLASSIC_V2}_{CLASSIC_PICK}_oof.npy",
                                                 f"{CLASSIC_V2}_v1_recipe_oof.npy", LLM_OOF)},
           "summary": summary, "diffs_vs_classical_v2": diffs, "latency": lat,
           "test_files_read": False, "seconds": round(time.time() - t0)}
    with open(f"{DECISION}.json", "w") as f:
        json.dump(tc2._jsonable(rep), f, indent=1)
    with open(f"{DECISION}.md", "w") as f:
        f.write(decision_md(tc2._jsonable(rep)))
    print(decision_md(tc2._jsonable(rep)))


def _pts(d: dict) -> str:
    return f"{100 * d['diff']:+.1f} pts [{100 * d['lo']:+.1f}, {100 * d['hi']:+.1f}]"


def decision_md(rep: dict) -> str:
    f = ec.fmt_rate
    o = [f"# frozen_near_v2: model decision (written {rep['written_at']}, before any test file was read)", "",
         f"**Choice: `{rep['choice']}`** (classical candidate `{rep['classical_candidate']}`).", "",
         f"Rule (fixed before computing these numbers): {rep['rule']}", "",
         f"Rows: `{rep['rows']['train_file']}` sha256 `{rep['rows']['train_sha256'][:16]}...`, {rep['rows']['n_rows']} "
         f"rows with their source file ({rep['rows']['no_file_excluded']} excluded), {rep['rows']['n_non_trivial']} "
         f"non-trivial; {rep['rows']['n_confirmed']} confirmed real vulnerabilities; "
         f"{rep['rows']['n_real_pairs_not_shorter']} real pairs whose vulnerable version is not shorter.", "",
         "## Reasons", ""] + [f"- {w}" for w in rep["reasons"]]
    o += ["", "## Numbers (out-of-fold on train_v2)", "",
          "| model | thresholds | block: confirmed | block: all real | block: clean files alarming | block: FPR contract "
          "| warn: confirmed | warn: all real | warn: clean files alarming | warn: mutation |", "|" + "---|" * 10]
    for n, x in rep["summary"].items():
        for kind in ("nested", "pooled"):
            if kind not in x:
                continue
            b, w = x[kind]["block"], x[kind]["warn"]
            o.append(f"| {n} | {kind} | {f(b['recall_confirmed'])} | {f(b['recall_real'])} | "
                     f"{f(b['clean_file_alarm_share'])} | {f(b['fpr_corpus_contract'])} | {f(w['recall_confirmed'])} | "
                     f"{f(w['recall_real'])} | {f(w['clean_file_alarm_share'])} | {f(w['recall_mutation'])} |")
    o += ["", "| model | PR-AUC | ROC real vs contract corpus | ROC real vs fixed | pair rank (all real pairs) | "
          "pair rank, vulnerable shorter | pair rank, vulnerable not shorter |", "|---|---|---|---|---|---|---|"]
    for n, x in rep["summary"].items():
        o.append(f"| {n} | {x['pr_auc']:.3f} | {x['roc_auc_real_vs_contract_corpus']:.3f} | "
                 f"{x['roc_auc_real_vs_fixed']:.3f} | {f(x['pair_rank_real'])} | {f(x['pair_rank_real_vuln_shorter'])} "
                 f"| {f(x['pair_rank_real_vuln_not_shorter'])} |")
    o += ["", "Differences against classical v2 (bootstrap over groups, 95%):", ""]
    for n, d in rep["diffs_vs_classical_v2"].items():
        o.append(f"- {n}: " + "; ".join(f"{k} {_pts(v)}" for k, v in d.items()))
    lat = rep["latency"]
    c = lat["classical_v2_big_contract"]
    o += ["", "## Latency", "",
          f"- Classical v2 on `{c['repo']}` at HEAD ({c['n_files']} .rs files, {c['n_functions']} functions, "
          f"{c['n_model_scored']} non-trivial): extraction {c['extract_s']} s, v2 featurization {c['featurize_s']} s, "
          "single process.",
          f"- LLM, measured per function by llm_classifier: {lat['llm_recorded_ms_per_fn']}; estimated for the same "
          f"{c['n_model_scored']} functions: {lat['llm_estimated_s_big_contract']} s.", ""]
    return "\n".join(o)


# --- stage 2: freeze ----------------------------------------------------------------------------------------------
LLM_DIR = "near/models/llm_final"
LLM_FINAL_RUN = "near/models/llm_qwen05_final/final"
MODEL_NAME = ("mean-rank ensemble of (a) classical v2: HGB (lr 0.1, 31 leaves, 300 iters, l2 1.0) on analyzer features "
              "computed with the function's file, per-detector counts, file / Cargo.toml context without the era "
              "columns and 1000 chi2-selected code tokens (train_classic_v2 ctx_fixed_noera), and (b) Qwen2.5-Coder-0.5B "
              "+ LoRA r16 with a pairwise loss, merged (llm_classifier qwen05_final); risk = mean of the two models' "
              "percentiles against their held-out training scores")
CONTRACT_RULE = ("contract risk = max ensemble risk over public, non-test, non-trivial contract-code functions (the LLM "
                 "runs on those only); high if >= block threshold, medium if >= warn, else low")


def llm_val_ids() -> set[str]:
    """Ids of the 1/5 of train_v2 groups that llm_final never trained on (llm_classifier.final_split)."""
    rows, _ = tc2.load_train(TRAIN)
    _, va = ec.group_folds(rows, 5, ec.SEED + 99)[0]
    n = read_json(f"{LLM_DIR}/oracle.json")["val_rows"]
    if len(va) != n:
        raise SystemExit(f"llm_final validation split has {len(va)} rows here, {n} in its oracle.json")
    return {rows[i]["id"] for i in va}


def training_files(r: dict) -> dict[str, str] | None:
    """The files the training featurization saw for row r (train_classic_v2._ctx_job): its scope files at the row's
    commit, a Cargo.toml missing at that commit read from HEAD; None when the function's file is unavailable."""
    d = tc2.repo_dir(r)
    listing = tc2.cx.git_listing(d, r["commit"]) if d and r.get("commit") else None
    if not listing or r["path"] not in listing:
        return None
    want = tc2.cx.scope_paths(listing, r["path"])
    files = tc2.cx.git_read(d, r["commit"], want)
    miss = [p for p in want if p.endswith("Cargo.toml") and p not in files]
    if miss:
        files.update(tc2.cx.git_read(d, "HEAD", miss))
    return files if r["path"] in files else None


def fit_class_head_v2(rows: list[dict], M: dict, est: dict) -> dict:
    """vuln_class head as v1's (freeze.fit_class_head) on the classical v2 design: multinomial LR (C=1) on label-1
    rows with a class, [dense blocks / max-abs | token hashes], protocol sample weights."""
    from sklearn.linear_model import LogisticRegression

    from near.model import predict
    dense = np.hstack([M[b] for b in est["blocks"] if b != "T"])
    head = {"amax": np.maximum(np.abs(dense).max(axis=0), 1e-9)}
    pos = np.array([r["label"] == 1 and bool(r.get("vuln_class")) for r in rows])
    X = predict.head_matrix(head, est, M)[pos]
    y = np.array([r["vuln_class"] for r in rows], object)[pos]
    head["clf"] = LogisticRegression(C=1.0, max_iter=300).fit(X, y, sample_weight=ec.sample_weights(rows)[pos])
    head["clf"].sparsify()
    return head


def score_llm(rows: list[dict], loaded, chunk: int = 2000, log=print) -> np.ndarray:
    from near.model import llm_classifier as L
    out = []
    for i in range(0, len(rows), chunk):
        out += L.score_rows(rows[i:i + chunk], loaded)
        log(f"  LLM scored {min(i + chunk, len(rows))}/{len(rows)}")
    return np.array(out)


def rate_table(rows: list[dict], s: np.ndarray, thr: dict) -> dict:
    conf = np.array([is_confirmed(r) for r in rows])
    m = ec.metrics(rows, s, {lvl: s >= t for lvl, t in thr.items()})
    return {lvl: {"recall_confirmed": ec.rate(s >= t, conf), "recall_real": m[lvl]["recall_real"],
                  "recall_mutation": m[lvl]["recall_mutation"], "fpr_corpus_contract": m[lvl]["fpr_corpus_contract"],
                  "fpr_paired_fixed": m[lvl]["fpr_paired_fixed"]} for lvl, t in thr.items()}


def freeze_stage(workers: int, n_check: int = 200) -> None:
    from near.model import llm_classifier as L
    from near.model import predict
    dec = read_json(f"{DECISION}.json")
    if dec["choice"] != "ensemble_mean_rank":
        raise SystemExit(f"decision is {dec['choice']}: this freeze implements the ensemble only")
    t0 = time.time()
    rows_all, scored, rows, M, info = load_train_features(workers)
    y = np.array([r["label"] for r in rows])
    cv = read_json(f"{CLASSIC_V2}.json")
    sel = cv["final_selection"][CLASSIC_PICK]
    params = sel["params"]
    print(f"{len(rows)} non-trivial rows with their file ({int(y.sum())} label-1); features {time.time() - t0:.0f}s",
          flush=True)

    # classical: grouped 3-fold OOF with the all-train selection's folds (train_classic_v2.final_selection)
    tc2._G.update(rows=rows, M=M, y=y)
    folds = ec.group_folds(rows, 3, ec.SEED + 100)
    oof = np.full(len(rows), np.nan)
    for (_, te), s in zip(folds, tc2.run_jobs([(CLASSIC_PICK, 0, tr, te) for tr, te in folds], workers)):
        oof[te] = s
    assert np.isfinite(oof).all(), "classical OOF scores missing"
    saved = np.load(f"{CLASSIC_V2}_final_{CLASSIC_PICK}_oof.npy")[scored]
    oof_matches = bool(np.allclose(oof, saved, atol=1e-9))
    thr_c = ec.thresholds_from(rows, oof)
    print(f"classical OOF thresholds {thr_c} (same OOF as the selection run: {oof_matches}); {time.time() - t0:.0f}s",
          flush=True)
    est = tc2.fit_model(params, tc2.BLOCKS[tc2.CANDIDATES[CLASSIC_PICK][0]], M, y,
                        tc2.weights(rows, params, tc2.CANDIDATES[CLASSIC_PICK][1]))
    head = fit_class_head_v2(rows, M, est)
    print(f"classical model and class head fitted; {time.time() - t0:.0f}s", flush=True)

    # LLM: the merged deployable model on the groups it never trained on
    oracle = read_json(f"{LLM_DIR}/oracle.json")
    if oracle["train_sha256"] != info["train_sha256"]:
        raise SystemExit("llm_final was trained on another train_v2")
    val_ids = llm_val_ids()
    vidx = np.array([i for i, r in enumerate(rows) if r["id"] in val_ids])
    vrows = [rows[i] for i in vidx]
    loaded = L.load_final(LLM_DIR)
    s_l = score_llm(vrows, loaded)
    from pathlib import Path
    adapter = L.read_scores(Path(f"{LLM_FINAL_RUN}/scores_val.jsonl"))
    from scipy.stats import spearmanr
    a = np.array([adapter[r["id"]] for r in vrows])
    llm_parity = {"n": len(vrows), "spearman_vs_adapter": float(spearmanr(a, s_l).statistic),
                  "max_abs_diff_vs_adapter": float(np.abs(a - s_l).max())}
    print(f"LLM on {len(vrows)} held-out rows: {llm_parity}; {time.time() - t0:.0f}s", flush=True)

    art = {"kind": "ensemble_v2", "version": TAG, "llm_dir": LLM_DIR, "llm_thresholds": oracle["thresholds"],
           "classical": {"estimator": est, "class_head": head, "params": params, "thresholds": thr_c},
           "ref_classical": np.sort(oof), "ref_llm": np.sort(s_l)}
    ens = predict.ensemble_risk(art, oof[vidx], s_l)
    art["thresholds"] = ec.thresholds_from(vrows, ens)
    print(f"ensemble thresholds {art['thresholds']} on {len(vrows)} rows", flush=True)

    # no-Cargo.toml sensitivity: the service fetches .rs files only, so the manifest column is -1 at inference
    oc = [j for j, k in enumerate(k for k in tc2.cx.CONTEXT_KEYS if k not in tc2.ERA_KEYS) if k == "ctx_overflow_checks"]
    s_full = tc2.predict_model(est, M)
    M_nt = dict(M, Xn=M["Xn"].copy())
    M_nt["Xn"][:, oc] = -1.0
    s_nt = tc2.predict_model(est, M_nt)
    sens = {"in_sample_final_model": {"with_manifest": rate_table(rows, s_full, thr_c),
                                      "manifest_missing": rate_table(rows, s_nt, thr_c)},
            "held_out_rows_ensemble": {"with_manifest": rate_table(vrows, ens, art["thresholds"]),
                                       "manifest_missing_classical_in_sample": rate_table(
                                           vrows, predict.ensemble_risk(art, s_nt[vidx], s_l), art["thresholds"])},
            "share_rows_overflow_unknown_in_train": float((M["Xn"][:, oc[0]] == -1).mean())}

    ids_path = f"{OUT}/{TAG}_train_ids.json"
    freeze.write_json(ids_path, sorted(r["id"] for r in rows))
    held = rate_table(vrows, ens, art["thresholds"])
    meta = {
        "model_name": MODEL_NAME, "kind": "ensemble_v2", "code_kind": "v2", "created": utc_now(),
        "decision": f"{DECISION}.json", "decision_sha256": tc2.sha256(f"{DECISION}.json"),
        "decision_written_at": dec["written_at"],
        "classical": {"candidate": CLASSIC_PICK, "params": params, "blocks": list(est["blocks"]),
                      "thresholds_oof": thr_c, "selection_thresholds": sel["oof_thresholds"],
                      "oof_matches_selection_run": oof_matches, "class_head_classes": [str(c) for c in head["clf"].classes_],
                      "n_features": int(est["clf"].n_features_in_)},
        "llm_dir": LLM_DIR, "llm_sha256": predict.llm_hashes(predict.ROOT / LLM_DIR), "llm_oracle": oracle,
        "llm_merge_parity_on_threshold_rows": llm_parity,
        "threshold_source": "ensemble risk on the 1/5 of train_v2 groups llm_final never trained on (non-trivial rows "
                            "with their file); classical scores there are grouped 3-fold OOF; lowest score with <= 1% / "
                            "5% of contract-code corpus negatives above it",
        "threshold_rows": len(vrows), "held_out_rates_at_thresholds": held,
        "rank_reference": {"classical": f"{len(oof)} grouped 3-fold OOF scores (non-trivial train rows)",
                           "llm": f"{len(s_l)} llm_final scores on its held-out groups"},
        "levels_fpr_on_contract_corpus": ec.LEVELS, "contract_rule": CONTRACT_RULE,
        "manifest_sensitivity": sens,
        "train_rows": len(rows), "train_positives": int(y.sum()),
        "train_positives_by_source": dict(Counter(r["source"] for r in rows if r["label"] == 1)),
        "train_groups": len({r["group"] for r in rows}), "train_rows_sha256": freeze.rows_sha256(rows),
        "train_file": TRAIN, "train_file_sha256": info["train_sha256"], "no_file_excluded": info["no_file_by"],
        "trivial_rows_excluded": int((~scored).sum()), "train_ids_file": ids_path,
        "train_ids_sha256": tc2.sha256(ids_path), "split_manifest": SPLIT_MANIFEST_V2,
        "split_manifest_sha256": tc2.sha256(SPLIT_MANIFEST_V2), "seed": ec.SEED,
        "llm_train_rows": oracle["train_rows"], "llm_note": "llm_final trained on 4/5 of the train_v2 groups (train_v2_small "
                                                            "rows); the classical model on all non-trivial train_v2 rows "
                                                            "with their file",
    }
    pkl = f"{OUT}/{TAG}.pkl"
    import pickle
    with open(pkl, "wb") as f:
        pickle.dump(art, f)
    meta.update(version=TAG, thresholds=art["thresholds"], pkl_sha256=predict.sha256_file(pkl),
                code_sha256=predict.code_hashes("v2"))
    freeze.write_json(freeze.manifest_path(pkl), tc2._jsonable(meta))
    print(f"wrote {pkl}; {time.time() - t0:.0f}s", flush=True)

    # reload and inference-path checks
    back = predict.load(pkl, cache=False)
    assert np.allclose(tc2.predict_model(back["classical"]["estimator"], M), s_full), "classical reload mismatch"
    rng = np.random.RandomState(ec.SEED)
    check, worst = [], {"classical": 0.0, "llm": 0.0, "ensemble": 0.0}
    for k in rng.permutation(len(vidx)):
        if len(check) >= n_check:
            break
        r = vrows[k]
        files = training_files(r)
        if files is None:
            continue
        out = predict.score_functions([r], back, file_src=files)[0]
        want_c = s_full[vidx[k]]
        worst["classical"] = max(worst["classical"], abs(out["classical_risk"] - want_c))
        worst["llm"] = max(worst["llm"], abs(out["llm_risk"] - s_l[k]))
        worst["ensemble"] = max(worst["ensemble"], abs(out["risk"] - predict.ensemble_risk(back, np.array([want_c]),
                                                                                            np.array([s_l[k]]))[0]))
        check.append(r["id"])
    print(f"predict-path check on {len(check)} held-out rows: max |diff| {worst}", flush=True)
    assert worst["classical"] < 1e-5, "predict.py classical featurization differs from training"
    meta.update(predict_path_check={"n": len(check), "max_abs_diff": worst}, seconds=round(time.time() - t0))
    freeze.write_json(freeze.manifest_path(pkl), tc2._jsonable(meta))
    print(json.dumps({k: v for k, v in tc2._jsonable(meta).items() if k not in ("code_sha256", "manifest_sensitivity",
                                                                               "llm_oracle")}, indent=1))


# --- stage 3: test_v1c, once ----------------------------------------------------------------------------------------
TEST_C = "near/data/test_v1c.jsonl"
TEST_V1 = "near/data/test_v1.jsonl"
SPLIT_MANIFEST_V1 = "near/data/split_manifest_v1.json"
REPORT = "near/model/reports/test_v1c_v2"
RESULTS = "near/model/reports/RESULTS.md"
POPULATIONS = ("file_available", "all_rows")
POPULATION_NOTE = (
    "Populations (fixed before scoring): `file_available` = test rows whose source file is in the local clone at the "
    "row's commit, the rows the v2 training used (train_v2 rows without their file were excluded from v2's fit and "
    "CV because only real positives lacked it); it is the primary population, and v1 is reported on the same rows. "
    "`all_rows` = every test row; v2 then scores the rows without their file from the function alone (the service "
    "always has the file, so this is not how v2 is deployed).")


def check_disjoint_all(trains: dict[str, list[dict]], test: list[dict]) -> list[str]:
    from near.model.score_sealed import check_disjoint
    return [f"{name}: {p}" for name, rows in trains.items() for p in check_disjoint(rows, test)]


def v2_scores(rows: list[dict], art: dict, loaded, workers: int) -> dict:
    """v2 on test rows through the training featurization (git context at each row's commit): ensemble risk,
    classical and LLM components (trivial rows -1, never alarming), class guess, file availability."""
    from near.model import predict
    M_all = tc2.featurize(rows, workers)
    triv = np.array([is_trivial(r["code"]) for r in rows])
    idx = np.where(~triv)[0]
    M = tc2.with_derived({k: M_all[k][idx] for k in ("A1", "D", "X", "T")})
    s_c = np.full(len(rows), -1.0)
    s_c[idx] = tc2.predict_model(art["classical"]["estimator"], M)
    s_l = np.full(len(rows), -1.0)
    s_l[idx] = score_llm([rows[i] for i in idx], loaded)
    ens = np.full(len(rows), -1.0)
    ens[idx] = predict.ensemble_risk(art, s_c[idx], s_l[idx])
    guess = [None] * len(rows)
    g, _ = predict.class_guess_v2(art["classical"]["class_head"], art["classical"]["estimator"], M)
    for k, i in enumerate(idx):
        guess[i] = g[k]
    return {"ensemble": ens, "classical": s_c, "llm": s_l, "guess": guess, "available": M_all["available"],
            "context_stats": M_all["stats"]}


def extra_test_metrics(rows: list[dict], s: np.ndarray, thr: dict) -> dict:
    """Recall by relabel verdict / v2 evidence bucket, pair rank split by length, alongside score_sealed.report."""
    hit = {lvl: s >= t for lvl, t in thr.items()}
    b = np.array([tc2.bucket(r) for r in rows], object)
    present = sorted({x for x in b if x})
    return {"buckets": {lvl: {k: ec.rate(h, b == k) for k in present} for lvl, h in hit.items()},
            "pair_rank_real": rate_of(pair_wins(s, *real_pairs(rows))),
            "pair_rank_real_vuln_not_shorter": rate_of(pair_wins(s, *real_pairs(rows, True))),
            "pair_rank_real_vuln_shorter": rate_of(pair_wins(s, *real_pairs(rows, False))),
            "pair_rank_shorter_is_riskier_control": rate_of(pair_wins(-np.array([len(r["code"]) for r in rows], float),
                                                                       *real_pairs(rows)))}


def score_stage(workers: int) -> None:
    from near.model import llm_classifier as L
    from near.model import predict
    from near.model import score_sealed as ss
    from near.model import train_classic as tc
    if os.path.exists(f"{REPORT}.json") or os.path.exists(f"{REPORT}.started"):
        raise SystemExit(f"{REPORT}.json (or .started) exists: test_v1c is scored once")
    if not os.path.exists(f"{DECISION}.json"):
        raise SystemExit("no model decision: run the decide stage first")
    dec = read_json(f"{DECISION}.json")
    pkl2 = f"{OUT}/{TAG}.pkl"
    art2, art1 = predict.load(pkl2), predict.load(predict.FROZEN_V1)
    man2, man1 = read_json(freeze.manifest_path(pkl2)), read_json(freeze.manifest_path(predict.FROZEN_V1))
    probs = []
    if man2["decision_sha256"] != tc2.sha256(f"{DECISION}.json"):
        probs.append("decision file changed since the freeze")
    train2, _ = tc2.load_train(TRAIN)
    if tc2.sha256(TRAIN) != man2["train_file_sha256"]:
        probs.append("train_v2 changed since the freeze")
    if set(read_json(man2["train_ids_file"])) - {r["id"] for r in train2}:
        probs.append("v2 train ids not all in train_v2")
    want = {TEST_C: read_json(SPLIT_MANIFEST_V2)["files"]["test_v1c.jsonl"]["sha256"],
            TEST_V1: read_json(SPLIT_MANIFEST_V1)["files"]["test_v1.jsonl"]["sha256"]}
    probs += [f"{p} sha256 differs from its split manifest" for p, h in want.items() if tc2.sha256(p) != h]
    train1, _ = tc.load_train(man1["train_file"])
    tests = {}
    for name, path in (("test_v1c", TEST_C), ("test_v1", TEST_V1)):
        with open(path) as f:
            tests[name] = [json.loads(line) for line in f]
        probs += check_disjoint_all({"train_v2": train2, "train_v1": train1}, tests[name])
    if probs:
        raise SystemExit("refusing to score:\n  " + "\n  ".join(probs))
    open(f"{REPORT}.started", "w").write(utc_now() + "\n")

    conflicts = {c["label0_id"] for c in read_json(ss.CONFLICTS)["test"]}
    loaded = L.load_final(predict.ROOT / art2["llm_dir"])
    rep = {"scored_at": utc_now(), "status": "DEVELOPMENT-INFORMED (not sealed)", "population_note": POPULATION_NOTE,
           "decision": {"file": f"{DECISION}.json", "sha256": man2["decision_sha256"], "written_at": dec["written_at"],
                        "choice": dec["choice"]},
           "models": {"v2": {**art2["info"], "name": man2["model_name"], "thresholds": art2["thresholds"]},
                      "v1": {**art1["info"], "name": man1["model_name"], "thresholds": art1["thresholds"]}},
           "tests": {}}
    for name, rows in tests.items():
        v2 = v2_scores(rows, art2, loaded, workers)
        s1, g1 = ss.score(rows, art1, workers)
        avail = v2["available"]
        t = {"file": TEST_C if name == "test_v1c" else TEST_V1, "sha256": tc2.sha256(TEST_C if name == "test_v1c" else TEST_V1),
             "n_rows": len(rows), "n_groups": len({r["group"] for r in rows}),
             "counts": dict(sorted(Counter(f"{r['source']}|{r['label']}" for r in rows).items())),
             "no_file_rows": dict(Counter(f"{r['source']}|{r['label']}" for r, a in zip(rows, avail) if not a)),
             "context_stats": v2["context_stats"], "populations": {}}
        comps = {"v2": (v2["ensemble"], v2["guess"], art2["thresholds"]),
                 "v1": (s1, g1, art1["thresholds"]),
                 "v2_classical_only": (v2["classical"], v2["guess"], art2["classical"]["thresholds"]),
                 "v2_llm_only": (v2["llm"], v2["guess"], art2["llm_thresholds"])}
        for pop in POPULATIONS:
            keep = np.where(avail)[0] if pop == "file_available" else np.arange(len(rows))
            sub = [rows[i] for i in keep]
            t["populations"][pop] = {}
            for model, (s, g, thr) in comps.items():
                r = ss.report(sub, s[keep], [g[i] for i in keep], thr, conflicts)
                r["extra"] = extra_test_metrics(sub, s[keep], thr)
                t["populations"][pop][model] = r
            print(f"{name} {pop}: " + "; ".join(
                f"{m} block real {ec.fmt_rate(x['block']['recall_real'])} warn {ec.fmt_rate(x['warn']['recall_real'])}"
                for m, x in t["populations"][pop].items()), flush=True)
        np.savez(f"{REPORT}_{name}_scores.npz", ids=np.array([r["id"] for r in rows]), v2=v2["ensemble"],
                 v2_classical=v2["classical"], v2_llm=v2["llm"], v1=s1, available=avail)
        rep["tests"][name] = t
    rep = tc2._jsonable(rep)
    freeze.write_json(f"{REPORT}.json", rep)
    with open(f"{REPORT}.md", "w") as f:
        f.write(test_md(rep))
    print(test_md(rep))


MODEL_COLS = ("v2", "v1", "v2_classical_only", "v2_llm_only")


def _incidents(x: dict) -> str:
    c = Counter(i["outcome"] for i in x["incidents"])
    return f"{c['block']} block / {c['warn']} warn / {c['missed']} missed of {len(x['incidents'])}"


def headline(pop: dict) -> list[str]:
    f = ec.fmt_rate
    fl = "contract_level_deployed_rule_by_file"
    lines = ["| | " + " | ".join(MODEL_COLS) + " |", "|---|" + "---|" * len(MODEL_COLS)]

    def row(label, get):
        vals = []
        for m in MODEL_COLS:
            try:
                v = get(pop[m])
            except (KeyError, TypeError):
                v = None
            vals.append("n/a" if v is None else v)
        lines.append(f"| {label} | " + " | ".join(vals) + " |")

    for lvl in ec.LEVELS:
        row(f"**{lvl}: recall, real label-1 (all)**", lambda x, l=lvl: f(x[l]["recall_real"]))
        row(f"{lvl}: recall, real severity != info", lambda x, l=lvl: f(x[l]["recall_real_noninfo"]))
        for b in ("confirmed", "plausible"):
            row(f"{lvl}: recall, relabel verdict {b}", lambda x, l=lvl, b=b: f(x["extra"]["buckets"][l][b])
                if x["extra"]["buckets"][l].get(b) else None)
        row(f"{lvl}: time split (real, dated >= 2025)", lambda x, l=lvl: f(x[l]["time_split_recall_real"]))
        row(f"{lvl}: recall, mutations", lambda x, l=lvl: f(x[l]["recall_mutation"]))
        row(f"{lvl}: false alarms, contract-code corpus", lambda x, l=lvl: f(x[l]["fpr_corpus_contract"]))
        row(f"{lvl}: false alarms, paired fixed versions", lambda x, l=lvl: f(x[l]["fpr_paired_fixed"]))
        row(f"{lvl}: corpus files holding no real label-1 alarming", lambda x, l=lvl: f(x[l][fl]["clean_files"]))
        row(f"{lvl}: files holding a real label-1 alarming",
            lambda x, l=lvl: f(x[l]["contract_level_deployed_rule"]["real_vuln_files"]))
    row("pair rank, all real pairs", lambda x: f(x["extra"]["pair_rank_real"]))
    row("pair rank, vulnerable not shorter than its fix", lambda x: f(x["extra"]["pair_rank_real_vuln_not_shorter"]))
    row("pair rank, control 'shorter = riskier'", lambda x: f(x["extra"]["pair_rank_shorter_is_riskier_control"]))
    row("PR-AUC", lambda x: f"{x['overall']['pr_auc']:.3f}")
    row("ROC-AUC real vs contract corpus", lambda x: f"{x['overall']['roc_auc_real_vs_contract_corpus']:.3f}")
    row("ROC-AUC real vs paired fixed", lambda x: f"{x['overall']['roc_auc_real_vs_fixed']:.3f}")
    row("held-out incidents (hacks)", _incidents)
    return lines


def detail_md(rep: dict, test: str, pop: str, model: str) -> str:
    """score_sealed's full report layout for one (test, population, model)."""
    from near.model import score_sealed as ss
    t, x = rep["tests"][test], rep["tests"][test]["populations"][pop][model]
    mk = "v2" if model.startswith("v2") else "v1"
    d = dict(x, scored_at=rep["scored_at"], model={"version": rep["models"][mk]["version"],
                                                    "sha256": rep["models"][mk]["sha256"]},
             model_name=rep["models"][mk]["name"], test_file=t["file"], test_sha256=t["sha256"], n_groups=t["n_groups"],
             counts=t["counts"])
    body = ss.render_md(d).split("\n", 1)[1]
    return f"## Detail: {model} on {test}, population `{pop}`\n" + body


def test_md(rep: dict) -> str:
    v2, v1 = rep["models"]["v2"], rep["models"]["v1"]
    o = [f"# test_v1c: frozen_near_v2 vs frozen_near_v1 (scored once, {rep['scored_at']})", "",
         "**DEVELOPMENT-INFORMED, not a sealed test.** test_v1c is test_v1 with cleaned labels. test_v1's aggregate "
         "v1 results (near/model/reports/sealed_test_v1.md) were seen before v2 was designed, and they shaped its "
         "design: the label cleaning, the context features, the ensemble. The cleaning itself was blind to model "
         "predictions. No v2 component was trained, tuned or thresholded on these rows; v2 was chosen on train_v2 "
         f"nested-CV numbers by a fixed rule (`{rep['decision']['file']}`, written {rep['decision']['written_at']}, "
         f"sha256 `{rep['decision']['sha256'][:16]}...`, choice `{rep['decision']['choice']}`) before this file was "
         "scored. These numbers are optimistic relative to a fresh sealed test.", "",
         f"- v2 `{v2['version']}` sha256 `{v2['sha256'][:16]}...`: {v2['name']}. Thresholds block "
         f"{v2['thresholds']['block']:.4f} / warn {v2['thresholds']['warn']:.4f} (ensemble percentile scale).",
         f"- v1 `{v1['version']}` sha256 `{v1['sha256'][:16]}...`: {v1['name']}. Thresholds block "
         f"{v1['thresholds']['block']:.4f} / warn {v1['thresholds']['warn']:.4f}.",
         "- Columns `v2_classical_only` / `v2_llm_only`: v2's two components alone at their own frozen thresholds "
         "(diagnostic, not deployed).", "", rep["population_note"], ""]
    for test, t in rep["tests"].items():
        labels = "cleaned labels" if test == "test_v1c" else "original labels, for continuity with sealed_test_v1"
        o += [f"## {test} ({labels})", "",
              f"`{t['file']}` sha256 `{t['sha256'][:16]}...`: {t['n_rows']} rows, {t['n_groups']} groups; "
              f"{t['counts']}. Rows without their source file in the local clone: {t['no_file_rows'] or 'none'}.", ""]
        for pop in POPULATIONS:
            o += [f"### {test}, population `{pop}`", ""] + headline(t["populations"][pop]) + [""]
    o += [detail_md(rep, "test_v1c", "file_available", m) for m in ("v2", "v1")]
    o += [detail_md(rep, "test_v1", "all_rows", "v1"), detail_md(rep, "test_v1", "all_rows", "v2")]
    return "\n".join(o) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["decide", "freeze", "score"])
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()
    if args.stage == "decide":
        decide(args.workers)
    elif args.stage == "freeze":
        freeze_stage(args.workers)
    else:
        score_stage(args.workers)


if __name__ == "__main__":
    main()
