"""Optional supervised head for the NEAR Intents detector, trained on sandbox attack variants (PLAN.md, "Optional
supervised head on synthetic variants"). It never sees a real positive.

Two stages, both pre-declared in PROTOCOL below, which was written before either stage was run:

    .venv/bin/python -m near.intents.head domain   # domain check; writes reports/head_domain_check.json
    .venv/bin/python -m near.intents.head train    # only if the domain check passed: fit, calibrate, evaluate, decide

The real normals come from the intents_v1 feature cache (near.intents.model). The domain check uses only train and
calibration months; the sealed test slice is read only by `train`, after the head and its thresholds are fixed.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

from near.intents import features as ft
from near.intents import model as md
from near.intents.collect import iter_jsonl_gz

SYN = md.DATA / "synthetic"
SYN_BENIGN = SYN / "benign.jsonl.gz"
SYN_ATTACKS = SYN / "attacks.jsonl.gz"
REPORTS = Path(__file__).parent / "reports"
DOMAIN_JSON = REPORTS / "head_domain_check.json"
HEAD_JSON = REPORTS / "head_evaluation.json"
HEAD_TAG = "intents_v1_head"

DOMAIN_AUC_MAX = 0.75
MAX_DROP_FRAC = 0.5
REAL_PER_SYN_MAX = 3
N_FOLDS = 5
MIN_GAIN = 5
SEED = 0
POSITIVE_ROLES = ("exploit", "attempt")

PROTOCOL = (
    "Domain check: rows are the synthetic benign sandbox txs (label 1, group = sandbox family) and real normals from "
    "the train and calibration months only (label 0, group = month), the real ones sampled per flow type to the "
    "synthetic flow mix with one common ratio (at most 3 real per synthetic, seed 0). Classifier: "
    "HistGradientBoostingClassifier (seed 0) on tx_features, out-of-fold ROC-AUC with 5-fold StratifiedGroupKFold. "
    "Pass: AUC <= 0.75. Otherwise drop, one at a time, the kept feature with the largest univariate |AUC - 0.5| on "
    "the same rows and re-run, for at most floor(0.5 * n_features) drops; if the AUC is still above 0.75 the head "
    "is not used. Head (only after a pass, on the kept features): the same classifier with balanced class weights, "
    "positives = all synthetic attack txs (exploit and attempt), negatives = synthetic benign plus real train-month "
    "normals. Head thresholds on calibration normals with md.alert_threshold, intents_v1's combined alerts using the "
    "budget first, so the combined calibration alert rate stays at most 1/10,000 (high) and 1/1,000 (medium). "
    "Combined label = max(intents_v1 label, head label). Adopt iff, on real held-out campaign txs with role exploit "
    "or attempt, medium-or-above detections rise by at least 5, AND on sealed test normals the head adds at most "
    "floor(n_test / 1,000) medium-or-above and at most floor(n_test / 10,000) high alerts. Thresholds are never "
    "tuned on the test slice or on real campaigns.")


# --- domain check ---------------------------------------------------------------------------------------------------

def flow_matched_sample(real_flows: np.ndarray, syn_flows: np.ndarray, max_ratio: float = REAL_PER_SYN_MAX,
                        seed: int = SEED) -> np.ndarray:
    """Indices into real_flows with the synthetic flow mix: floor(r * n_syn[f]) per flow f, one common ratio r =
    min(max_ratio, min_f n_real[f] / n_syn[f]), so the flow one-hots carry no domain signal."""
    rng = np.random.default_rng(seed)
    n_syn = Counter(syn_flows.tolist())
    n_real = Counter(real_flows.tolist())
    r = min([max_ratio] + [n_real.get(f, 0) / n for f, n in n_syn.items()])
    out = []
    for f in sorted(n_syn):
        pool = np.where(real_flows == f)[0]
        out.append(rng.choice(pool, size=math.floor(r * n_syn[f] + 1e-9), replace=False))
    return np.sort(np.concatenate(out)) if out else np.array([], int)


def domain_auc(X: np.ndarray, y: np.ndarray, groups: np.ndarray, seed: int = SEED) -> float:
    """Out-of-fold ROC-AUC of a classifier telling the two domains apart, folds grouped by `groups`."""
    oof = np.zeros(len(y))
    cv = StratifiedGroupKFold(n_splits=N_FOLDS, shuffle=True, random_state=seed)
    for tr, te in cv.split(X, y, groups):
        clf = HistGradientBoostingClassifier(random_state=seed).fit(X[tr], y[tr])
        oof[te] = clf.predict_proba(X[te])[:, 1]
    return float(roc_auc_score(y, oof))


def univariate_separation(X: np.ndarray, y: np.ndarray) -> np.ndarray:
    """|ROC-AUC - 0.5| of each column on its own."""
    return np.array([abs(roc_auc_score(y, X[:, j]) - 0.5) for j in range(X.shape[1])])


def domain_check(Xs, gs, Xr, gr, keys) -> dict:
    X = np.vstack([Xs, Xr]).astype(np.float64)
    y = np.r_[np.ones(len(Xs)), np.zeros(len(Xr))]
    g = np.r_[np.asarray(gs, object), np.asarray(gr, object)].astype(str)
    keys = list(keys)
    kept = list(range(len(keys)))
    sep0 = univariate_separation(X, y)
    steps = [{"drop": None, "auc": domain_auc(X, y, g)}]
    budget = math.floor(MAX_DROP_FRAC * len(keys))
    while steps[-1]["auc"] > DOMAIN_AUC_MAX and len(steps) - 1 < budget:
        sep = univariate_separation(X[:, kept], y)
        j = kept[int(np.argmax(sep))]
        kept.remove(j)
        steps.append({"drop": keys[j], "univariate_sep": float(sep.max()), "auc": domain_auc(X[:, kept], y, g)})
    top = np.argsort(-sep0)[:15]
    return {"protocol": PROTOCOL, "n_synthetic": len(Xs), "n_real": len(Xr), "auc_all_features": steps[0]["auc"],
            "steps": steps, "dropped": [s["drop"] for s in steps[1:]], "kept": [keys[j] for j in kept],
            "passed": steps[-1]["auc"] <= DOMAIN_AUC_MAX, "drop_budget": budget,
            "top_univariate_separation": [{"feature": keys[j], "abs_auc_minus_half": float(sep0[j]),
                                           "syn_mean": float(Xs[:, j].mean()), "real_mean": float(Xr[:, j].mean())}
                                          for j in top]}


# --- head thresholds and the adoption rule ----------------------------------------------------------------------

def head_thresholds(p_calib: np.ndarray, base_labels: np.ndarray) -> dict:
    """Head probability thresholds on calibration normals; intents_v1's alerts use the rate budget first."""
    hi = md.alert_threshold(p_calib, base_labels == "high", md.HIGH_RATE)
    med = min(md.alert_threshold(p_calib, base_labels != "low", md.MEDIUM_RATE), hi)
    return {"high": hi, "medium": med}


def combine_labels(base_labels: np.ndarray, p: np.ndarray, thr: dict) -> np.ndarray:
    rank = {"low": 0, "medium": 2, "high": 3}
    b = np.array([rank[x] for x in base_labels], np.int8)
    return md.labels_for(b, np.asarray(p, np.float64), thr)


def decide(pos_base: int, pos_head: int, test_fa_added_med: int, test_fa_added_high: int, n_test: int) -> dict:
    gain = pos_head - pos_base
    med_cap = math.floor(n_test * md.MEDIUM_RATE)
    high_cap = math.floor(n_test * md.HIGH_RATE)
    checks = {f"gain {gain} >= {MIN_GAIN}": gain >= MIN_GAIN,
              f"added test medium+ {test_fa_added_med} <= {med_cap}": test_fa_added_med <= med_cap,
              f"added test high {test_fa_added_high} <= {high_cap}": test_fa_added_high <= high_cap}
    return {"adopt": all(checks.values()), "checks": checks}


# --- stages -------------------------------------------------------------------------------------------------------

def featurize_synthetic(path) -> dict:
    d = md.featurize(iter_jsonl_gz(path))
    d["group"] = np.array([str(c) for c in d["campaign"]], dtype=object)
    return d


def run_domain() -> dict:
    cache = md.load_cache()
    N = cache["normals"]
    sp = md.split_masks(N["month"])
    dev = np.where(sp["train"] | sp["calib"])[0]
    S = featurize_synthetic(SYN_BENIGN)
    sflows = S["flow"].astype(str)
    pick = dev[flow_matched_sample(N["flow"][dev].astype(str), sflows)]
    rep = domain_check(S["X"], S["group"], N["X"][pick], N["month"][pick].astype(str), ft.FEATURE_KEYS)
    rep["synthetic_flows"] = dict(Counter(sflows.tolist()))
    rep["real_flows"] = dict(Counter(N["flow"][pick].astype(str).tolist()))
    rep["synthetic_groups"] = dict(Counter(S["group"].tolist()))
    rep["features_sha256"] = md.sha256_file(md.ROOT / "near/intents/features.py")
    rep["at"] = md.utc_now()
    REPORTS.mkdir(parents=True, exist_ok=True)
    DOMAIN_JSON.write_text(json.dumps(rep, indent=1))
    print(json.dumps({k: rep[k] for k in ("auc_all_features", "steps", "passed")}, indent=1))
    return rep


def positive_mask(roles: np.ndarray) -> np.ndarray:
    return np.array([r in POSITIVE_ROLES for r in roles], bool)


def fit_head(Xpos: np.ndarray, Xneg: np.ndarray, seed: int = SEED) -> HistGradientBoostingClassifier:
    X = np.vstack([Xpos, Xneg]).astype(np.float64)
    y = np.r_[np.ones(len(Xpos)), np.zeros(len(Xneg))]
    return HistGradientBoostingClassifier(class_weight="balanced", random_state=seed).fit(X, y)


def _medium_plus(lab) -> int:
    return int((np.asarray(lab) != "low").sum())


def _counts(lab) -> dict:
    lab = np.asarray(lab)
    return {"n": len(lab), "high": int((lab == "high").sum()), "medium": int((lab == "medium").sum()),
            "missed": int((lab == "low").sum())}


def run_train() -> dict:
    from near.intents.evaluate import campaign_key, rate

    dom = json.loads(DOMAIN_JSON.read_text())
    if not dom["passed"]:
        raise SystemExit(f"domain check failed (AUC {dom['steps'][-1]['auc']:.3f} > {DOMAIN_AUC_MAX} after "
                         f"{len(dom['dropped'])} drops): the head is not used; intents_v1 is unchanged")
    cols = [ft.FEATURE_KEYS.index(k) for k in dom["kept"]]
    cache = md.load_cache()
    art = md.load_artifact()
    N, L = cache["normals"], cache["labelled"]
    sp = md.split_masks(N["month"])
    S, A = featurize_synthetic(SYN_BENIGN), featurize_synthetic(SYN_ATTACKS)
    clf = fit_head(A["X"][:, cols], np.vstack([S["X"][:, cols], N["X"][sp["train"]][:, cols]]))

    def base_and_p(X, flows, rule_sev):
        s = md.score_matrix(art, X, flows)
        return md.labels_for(rule_sev, s, art["thresholds"]), clf.predict_proba(X[:, cols].astype(np.float64))[:, 1]

    def part(mask):
        return base_and_p(N["X"][mask], N["flow"][mask].astype(str), N["rule_sev"][mask])

    b_ca, p_ca = part(sp["calib"])
    thr = head_thresholds(p_ca, b_ca)
    c_ca = combine_labels(b_ca, p_ca, thr)
    out = {"protocol": PROTOCOL, "kept_features": dom["kept"], "dropped_features": dom["dropped"],
           "domain_auc": dom["steps"][-1]["auc"], "head_thresholds": thr,
           "n_train": {"synthetic_attacks": len(A["ids"]), "synthetic_benign": len(S["ids"]),
                       "real_train_normals": int(sp["train"].sum())},
           "calib": {"n": int(sp["calib"].sum()), "base": _counts(b_ca), "combined": _counts(c_ca),
                     "head_p_quantiles": {q: float(np.quantile(p_ca, q)) for q in (0.5, 0.99, 0.999, 1.0)}}}

    # sealed test normals: scored once, thresholds already fixed above
    b_te, p_te = part(sp["test"])
    c_te = combine_labels(b_te, p_te, thr)
    flows_te = N["flow"][sp["test"]].astype(str)
    added_med = (c_te != "low") & (b_te == "low")
    added_high = (c_te == "high") & (b_te != "high")
    n_te = int(sp["test"].sum())
    out["test"] = {"n": n_te, "base": _counts(b_te), "combined": _counts(c_te),
                   "base_medium_plus": rate(_medium_plus(b_te), n_te),
                   "combined_medium_plus": rate(_medium_plus(c_te), n_te),
                   "added_medium_plus": int(added_med.sum()), "added_high": int(added_high.sum()),
                   "added_by_flow": dict(Counter(flows_te[added_med].tolist()))}

    # real campaigns (never seen by the head)
    b_L, p_L = base_and_p(L["X"], L["flow"].astype(str), L["rule_sev"])
    c_L = combine_labels(b_L, p_L, thr)
    keys = np.array([campaign_key(c, r) for c, r in zip(L["campaign"], L["role"])])
    out["cases"] = {k: {"base": _counts(b_L[keys == k]), "combined": _counts(c_L[keys == k]),
                        "head_p_median": float(np.median(p_L[keys == k]))} for k in sorted(set(keys.tolist()))}
    pos = positive_mask(L["role"])
    out["real_positives"] = {"n": int(pos.sum()), "base_medium_plus": _medium_plus(b_L[pos]),
                             "combined_medium_plus": _medium_plus(c_L[pos]),
                             "base_high": int((b_L[pos] == "high").sum()),
                             "combined_high": int((c_L[pos] == "high").sum())}

    # synthetic attacks against the fixed verifier: out-of-sample sandbox txs, head alone
    F = featurize_synthetic(SYN / "fixed_v0.4.3-backport.jsonl.gz")
    pF = clf.predict_proba(F["X"][:, cols].astype(np.float64))[:, 1]
    out["fixed_verifier_synthetic"] = {
        r: {"n": int((F["role"] == r).sum()), "head_medium_plus": int((pF[F["role"] == r] >= thr["medium"]).sum())}
        for r in sorted(set(F["role"].tolist()))}

    rp = out["real_positives"]
    out["decision"] = decide(rp["base_medium_plus"], rp["combined_medium_plus"], out["test"]["added_medium_plus"],
                             out["test"]["added_high"], n_te)
    out["at"] = md.utc_now()
    HEAD_JSON.write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps(out, indent=1, default=str))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("stage", choices=["domain", "train"])
    a = ap.parse_args(argv)
    run_domain() if a.stage == "domain" else run_train()


if __name__ == "__main__":
    main()
