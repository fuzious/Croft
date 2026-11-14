"""Shared evaluation protocol for NEAR code-risk models: weights, grouped folds, nested CV, protocol metrics.

Mirrors scripts/eval_nested.py: outer GroupKFold over `group`; inside each outer-train split the model picks its
hyperparameters on inner group folds, the alarm thresholds come from inner out-of-fold scores (FPR 1% = block,
5% = warn, measured on contract-code corpus negatives), then the outer-test fold is scored once with them.

API (stable; the encoder trainer imports it read-only):
    nested_group_cv(fit_predict_fn, rows, outer=5, inner=3, seed=SEED) -> {"scores", "decisions", "thresholds", ...}
    metrics(rows, scores, decisions=None) -> dict with every protocol number (Wilson 95% CIs on rates)
"""
from __future__ import annotations

import math
import re
from collections import defaultdict

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import GroupKFold

SEED = 20261114
REAL = ("audit", "incident", "fix_commit")
LEVELS = {"block": 0.01, "warn": 0.05}  # per-function FPR on contract-code corpus negatives
TEST_PATH = re.compile(r"(^|/)(tests?|unit_tests|test_utils?|integration-tests|sandbox|mock\w*)(/|\.rs$)|_test\.rs$"
                       r"|test_utils\.rs$", re.I)
OFFCHAIN_PATH = re.compile(r"(^|/)(node|indexer|service|services|cli|agent|relayer|bot|scripts|tools|xtask"
                           r"|bench(es)?)(/|$)", re.I)
ASYNC_FN = re.compile(r"\basync\s+fn\b")


def is_real(r: dict) -> bool:
    return r["source"] in REAL


def is_contract_code(r: dict) -> bool:
    """Not async, not a test helper, not under an off-chain directory (split audit P4 definition)."""
    return not (ASYNC_FN.search(r["code"]) or TEST_PATH.search(r["path"] or "") or OFFCHAIN_PATH.search(r["path"] or "")
                or r.get("is_test"))


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def rate(mask_hit: np.ndarray, mask_pop: np.ndarray) -> dict:
    k, n = int((mask_hit & mask_pop).sum()), int(mask_pop.sum())
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": k / n if n else float("nan"), "lo": lo, "hi": hi}


def sample_weights(rows: list[dict], real_to_mutation: float = 1.0, info_weight: float | None = None) -> np.ndarray:
    """Training weights: field `weight` (severity: info 0.3, low 0.6) on real rows, rescaled so total real label-1
    weight = real_to_mutation x total mutation weight; real label-0 (fixed versions) get the same factor. Others 1.
    info_weight overrides the field weight of severity-info real rows (0 drops them)."""
    w = np.array([float(r.get("weight") or 1.0) if is_real(r) else 1.0 for r in rows])
    if info_weight is not None:
        w[np.array([is_real(r) and r.get("severity") == "info" for r in rows])] = info_weight
    real = np.array([is_real(r) for r in rows])
    real_pos = real & np.array([r["label"] == 1 for r in rows])
    mut = np.array([r["source"] == "mutation" for r in rows])
    if real_pos.any() and mut.any():
        w[real] *= real_to_mutation * w[mut].sum() / w[real_pos].sum()
    return w


def group_folds(rows_or_groups, k: int, seed: int = SEED) -> list[tuple[np.ndarray, np.ndarray]]:
    """GroupKFold over `group` with the group order shuffled by `seed` (GroupKFold itself is deterministic)."""
    names = [g if isinstance(g, str) else g["group"] for g in rows_or_groups]
    uniq = sorted(set(names))
    perm = np.random.RandomState(seed).permutation(len(uniq))
    code = {g: perm[i] for i, g in enumerate(uniq)}
    gid = np.array([code[g] for g in names])
    return [(tr, te) for tr, te in GroupKFold(k).split(np.zeros(len(gid)), groups=gid)]


def threshold_at_fpr(scores: np.ndarray, neg_mask: np.ndarray, fpr: float) -> float:
    """Lowest threshold t (alarm = score >= t) with at most floor(fpr * n_neg) negatives alarming."""
    neg = np.sort(np.asarray(scores)[neg_mask])[::-1]
    if len(neg) == 0:
        return math.inf
    k = int(math.floor(fpr * len(neg)))
    return -math.inf if k >= len(neg) else float(np.nextafter(neg[k], np.inf))


def calibration_negatives(rows: list[dict]) -> np.ndarray:
    return np.array([r["source"] == "corpus" and r["label"] == 0 and is_contract_code(r) for r in rows])


def thresholds_from(rows: list[dict], scores: np.ndarray) -> dict[str, float]:
    neg = calibration_negatives(rows)
    return {lvl: threshold_at_fpr(scores, neg, f) for lvl, f in LEVELS.items()}


def nested_group_cv(fit_predict_fn, rows: list[dict], outer: int = 5, inner: int = 3, seed: int = SEED,
                    log=print) -> dict:
    """fit_predict_fn(rows, train_idx, test_idx, inner_folds) -> {"scores": array for test_idx,
    optional "train_oof": inner out-of-fold scores for train_idx (selected config), optional "params"}.
    inner_folds: group-aware (tr, te) index arrays into `rows`, all inside train_idx; None means "fit with the
    params you would pick, no selection" (used to get inner OOF scores when train_oof is not returned).
    Returns pooled outer scores, per-row decisions at each level (thresholds from inner OOF), per-fold info."""
    n = len(rows)
    scores, fold_of = np.full(n, np.nan), np.full(n, -1)
    decisions = {lvl: np.zeros(n, bool) for lvl in LEVELS}
    thresholds = {lvl: [] for lvl in LEVELS}
    params = []
    for f, (tr, te) in enumerate(group_folds(rows, outer, seed)):
        sub = [rows[i] for i in tr]
        inner_folds = [(tr[a], tr[b]) for a, b in group_folds(sub, inner, seed + 1 + f)]
        out = fit_predict_fn(rows, tr, te, inner_folds)
        oof = out.get("train_oof")
        if oof is None:
            oof_full = np.full(n, np.nan)
            for itr, ite in inner_folds:
                oof_full[ite] = fit_predict_fn(rows, itr, ite, None)["scores"]
            oof = oof_full[tr]
        thr = thresholds_from(sub, np.asarray(oof))
        s = np.asarray(out["scores"], float)
        scores[te], fold_of[te] = s, f
        for lvl, t in thr.items():
            thresholds[lvl].append(t)
            decisions[lvl][te] = s >= t
        params.append(out.get("params"))
        log(f"  outer fold {f}: train {len(tr)} test {len(te)} thresholds "
            + " ".join(f"{k}={v:.4g}" for k, v in thr.items()) + (f" params {out.get('params')}" if out.get("params") else ""))
    return {"scores": scores, "decisions": decisions, "thresholds": thresholds, "fold": fold_of, "params": params}


def _masks(rows: list[dict]) -> dict[str, np.ndarray]:
    y = np.array([r["label"] == 1 for r in rows])
    real = np.array([is_real(r) for r in rows])
    src = np.array([r["source"] for r in rows])
    info = np.array([r.get("severity") == "info" for r in rows])
    corpus = (src == "corpus") & ~y
    return {"y": y, "real_pos": real & y, "real_pos_noninfo": real & y & ~info, "real_pos_info": real & y & info,
            "mutation": (src == "mutation") & y, "corpus": corpus,
            "corpus_contract": corpus & np.array([is_contract_code(r) for r in rows]),
            "paired_fixed": real & ~y, "mutation_original": (src == "mutation_original") & ~y}


def _auc(fn, y, s, w=None):
    return float(fn(y, s, sample_weight=w)) if 0 < y.sum() < len(y) else float("nan")


def selection_score(rows: list[dict], scores: np.ndarray) -> float:
    """Inner-fold model-selection objective: 0.75 x recall on real non-info label-1 + 0.25 x mutation recall, both at
    the 5% contract-code corpus FPR threshold (what the oracle's warn level would catch)."""
    m = _masks(rows)
    t = threshold_at_fpr(scores, m["corpus_contract"], LEVELS["warn"])
    hit = scores >= t
    real = rate(hit, m["real_pos_noninfo"])["rate"]
    mut = rate(hit, m["mutation"])["rate"]
    return float(0.75 * np.nan_to_num(real) + 0.25 * np.nan_to_num(mut))


def pair_rank(rows: list[dict], scores: np.ndarray) -> dict:
    """Share of real (vulnerable, fixed) pairs where the vulnerable version scores higher (ties count half)."""
    pos = {r["id"]: i for i, r in enumerate(rows)}
    wins = []
    for i, r in enumerate(rows):
        j = pos.get(r.get("pair_id"))
        if is_real(r) and r["label"] == 1 and j is not None and rows[j]["label"] == 0:
            wins.append(1.0 if scores[i] > scores[j] else 0.5 if scores[i] == scores[j] else 0.0)
    k, n = float(sum(wins)), len(wins)
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": k / n if n else float("nan"), "lo": lo, "hi": hi}


def contract_recall(rows: list[dict], hit: np.ndarray) -> dict:
    """Files (group, path) holding a real label-1 row: alarm if that row or any public fn of the file alarms.
    Corpus rows of the file may come from another commit than the vulnerable one (approximation)."""
    vuln = {(r["group"], r["path"]) for r in rows if is_real(r) and r["label"] == 1}
    files = dict.fromkeys(vuln, False)
    for i, r in enumerate(rows):
        key = (r["group"], r["path"])
        if key in files and ((is_real(r) and r["label"] == 1) or (r["source"] == "corpus" and r.get("is_public"))):
            files[key] |= bool(hit[i])
    v = np.array(list(files.values()), bool)
    return rate(v, np.ones(len(v), bool))


def contract_alarms(rows: list[dict], hit: np.ndarray) -> dict:
    """Corpus files (group, path) from groups with no real label-1 row: alarm if any public fn alarms."""
    dirty = {r["group"] for r in rows if is_real(r) and r["label"] == 1}
    files = defaultdict(bool)
    for i, r in enumerate(rows):
        if r["source"] == "corpus" and r["group"] not in dirty and r.get("is_public") and not r.get("is_test"):
            files[(r["group"], r["path"])] |= bool(hit[i])
    v = np.array(list(files.values()), bool)
    return rate(v, np.ones(len(v), bool))


def metrics(rows: list[dict], scores, decisions: dict | None = None) -> dict:
    """All protocol numbers. decisions = per-row alarms per level (from nested_group_cv); if None, thresholds are
    taken from these scores' own contract-code corpus negatives (pooled, optimistic)."""
    s = np.asarray(scores, float)
    m = _masks(rows)
    y = m["y"]
    pooled_thr = thresholds_from(rows, s)
    rp_vs_corpus = m["real_pos"] | m["corpus_contract"]
    out = {
        "n": len(rows), "n_pos": int(y.sum()),
        "pr_auc": _auc(average_precision_score, y, s), "roc_auc": _auc(roc_auc_score, y, s),
        "pr_auc_weighted": _auc(average_precision_score, y, s, sample_weights(rows)),
        "roc_auc_real_vs_contract_corpus": _auc(roc_auc_score, y[rp_vs_corpus], s[rp_vs_corpus]),
        "roc_auc_mutation_vs_contract_corpus": _auc(roc_auc_score, y[m["mutation"] | m["corpus_contract"]],
                                                    s[m["mutation"] | m["corpus_contract"]]),
        "roc_auc_real_vs_fixed": _auc(roc_auc_score, y[m["real_pos"] | m["paired_fixed"]],
                                      s[m["real_pos"] | m["paired_fixed"]]),
        "pair_rank_acc": pair_rank(rows, s),
        "pooled_thresholds": pooled_thr,
        "thresholds_source": "nested inner OOF" if decisions is not None else "pooled on these scores",
    }
    classes = sorted({r["vuln_class"] for r in rows if is_real(r) and r["label"] == 1 and r["vuln_class"]})
    vc = np.array([r.get("vuln_class") for r in rows], object)
    for lvl in LEVELS:
        hit = decisions[lvl] if decisions is not None else s >= pooled_thr[lvl]
        out[lvl] = {
            "recall_real": rate(hit, m["real_pos"]), "recall_real_noninfo": rate(hit, m["real_pos_noninfo"]),
            "recall_real_info": rate(hit, m["real_pos_info"]), "recall_mutation": rate(hit, m["mutation"]),
            "fpr_corpus": rate(hit, m["corpus"]), "fpr_corpus_contract": rate(hit, m["corpus_contract"]),
            "fpr_paired_fixed": rate(hit, m["paired_fixed"]), "fpr_mutation_original": rate(hit, m["mutation_original"]),
            "recall_class_real": {c: rate(hit, m["real_pos"] & (vc == c)) for c in classes},
            "recall_class_mutation": {c: rate(hit, m["mutation"] & (vc == c))
                                      for c in sorted(set(vc[m["mutation"]]) - {None})},
            "contract_alarm_share": contract_alarms(rows, hit),
            "contract_recall_real": contract_recall(rows, hit),
        }
    return out


def fmt_rate(d: dict, pct: bool = True) -> str:
    if not d["n"]:
        return "n/a"
    f = (lambda x: f"{100 * x:.1f}%") if pct else (lambda x: f"{x:.3f}")
    return f"{d['k']}/{d['n']} = {f(d['rate'])} [{f(d['lo'])}, {f(d['hi'])}]"
