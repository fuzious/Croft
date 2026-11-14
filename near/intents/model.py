"""NEAR Intents transaction anomaly model: featurize, split by time, select, calibrate thresholds, freeze, predict.

The anomaly model learns only from normal intents.near transactions (near/data/intents/normals.jsonl.gz). Real attack
campaigns (labelled.jsonl.gz) are never read here; near.intents.evaluate reports them as held-out case studies.

Split by the block month of each normal (_meta.month):
- train: up to TRAIN_LAST (fits the anomaly models);
- calibration: CALIB_FIRST to CALIB_LAST (model selection by DECISION_RULE and alert thresholds);
- test: from TEST_FIRST on, sealed: only near.intents.evaluate reads it, once, after this freeze.

Combined label: `high` if a high rule fires or the anomaly score reaches the high threshold; `medium` likewise with
medium rules and the medium threshold; else `low`. Thresholds keep the combined alert rate on calibration normals at
or below 1/10,000 (high) and 1/1,000 (medium). Displayed risk = max(rule severity weight, anomaly percentile), the
percentile taken against the training normals' scores.

    .venv/bin/python -m near.intents.model cache    # featurize normals + labelled once (about 1 min)
    .venv/bin/python -m near.intents.model freeze   # fit, select, calibrate; writes near/models/intents_v1.*
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import pickle
import time
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

from near.intents import features as ft
from near.intents.collect import any_receipt_failed, iter_jsonl_gz

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "near" / "data" / "intents"
NORMALS = DATA / "normals.jsonl.gz"
LABELLED = DATA / "labelled.jsonl.gz"
OUT = ROOT / "near" / "models"
TAG = "intents_v1"
CACHE = OUT / f"{TAG}.cache.pkl"
CODE_FILES = ("near/intents/features.py", "near/intents/model.py")

TRAIN_LAST = "2026-05"
CALIB_FIRST, CALIB_LAST = "2026-06", "2026-09"
TEST_FIRST = "2026-10"
HIGH_RATE = 1 / 10_000
MEDIUM_RATE = 1 / 1_000
SEV_RANK = {None: 0, "low": 1, "medium": 2, "high": 3}
TOP_K = 3
SEED = 0

DECISION_RULE = (
    "Candidates, both fitted on train normals only: (A) iforest_global, IsolationForest (300 trees, 2048 samples, "
    "seed 0) on robust-standardized tx_features; (B) tail_per_flow, per-flow-type empirical tail model (score = sum "
    "of the 3 largest -log10 two-sided tail probabilities of the features against train normals of the same flow "
    "type). (0) Eligible: the candidate's highest attainable score in every flow type present in train reaches its "
    "own calibrated medium threshold (otherwise its anomaly part cannot alert on that flow at all). (1) Rules' high "
    "hits are kept by construction (label = max of rules and anomaly), so the choice is made on known-normal failure "
    "modes only: on calibration normals with at least one failed receipt, the eligible candidate with the lower mean "
    "anomaly percentile (against its own train scores) wins. Tie (difference < 0.005): fewer failing calibration "
    "normals at medium or above with the candidate's own calibrated thresholds; still tied: tail_per_flow "
    "(interpretable). No attack transaction is used.")
SELECTION_NOTE = (
    "Eligibility (0) was added after the first freeze run, which applied rule (1) alone and picked tail_per_flow. "
    "Its output showed that tail_per_flow's highest attainable score is TOP_K * log10((n_flow + 1) / 2), below its "
    "medium threshold for deposit, other and withdrawal, so its anomaly part could only alert on execute_intents. "
    "That first run is kept in near/intents/reports/freeze_first_pass.json. No attack transaction and no test-slice "
    "row was read by either run.")


# --- small helpers --------------------------------------------------------------------------------------------------

def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def sha256_json(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def code_hashes(root=ROOT) -> dict[str, str]:
    return {f: sha256_file(Path(root) / f) for f in CODE_FILES}


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def max_severity(sevs) -> str | None:
    return max(sevs, key=SEV_RANK.__getitem__, default=None)


def label_for(rule_sev: str | None, score: float, thr: dict) -> str:
    if rule_sev == "high" or score >= thr["high"]:
        return "high"
    if rule_sev == "medium" or score >= thr["medium"]:
        return "medium"
    return "low"


def labels_for(rule_sev: np.ndarray, scores: np.ndarray, thr: dict) -> np.ndarray:
    """Vectorized label_for; rule_sev holds SEV_RANK integers."""
    out = np.full(len(scores), "low", dtype=object)
    out[(rule_sev >= 2) | (scores >= thr["medium"])] = "medium"
    out[(rule_sev >= 3) | (scores >= thr["high"])] = "high"
    return out


def alert_threshold(scores: np.ndarray, forced: np.ndarray, rate: float) -> float:
    """Smallest anomaly-score threshold t such that #(forced | scores >= t) <= floor(rate * n) on these calibration
    rows. Rows already alerting through rules (forced) use the budget first; if they exceed it the anomaly part is
    disabled (inf). Ties at the cut are never split, so the result can alert fewer rows than the budget."""
    budget = math.floor(rate * len(scores)) - int(forced.sum())
    if budget < 0:
        return math.inf
    rest = np.sort(scores[~forced])[::-1]
    if len(rest) == 0:
        return math.inf
    if budget >= len(rest):
        return float(rest[-1])
    return float(np.nextafter(rest[budget], np.inf))


# --- anomaly models -------------------------------------------------------------------------------------------------

class TailModel:
    """Per-flow-type empirical tail model. For each feature, the two-sided tail probability of a value among the
    training normals of the same flow type, p = min(1, 2 * (min(#<=x, #>=x) + 1) / (n + 1)); the score is the sum of
    the TOP_K largest -log10 p. Unknown flow types use all training rows."""

    def __init__(self, feature_keys):
        self.keys = list(feature_keys)
        self.ref: dict[str, np.ndarray] = {}

    def fit(self, X: np.ndarray, flows: np.ndarray) -> "TailModel":
        X = np.asarray(X, np.float32)
        self.ref = {"*": np.sort(X, axis=0)}
        for f in sorted(set(flows.tolist())):
            self.ref[f] = np.sort(X[flows == f], axis=0)
        return self

    def _neglogp(self, X: np.ndarray, ref: np.ndarray) -> np.ndarray:
        n = len(ref)
        out = np.empty(X.shape, np.float64)
        for j in range(X.shape[1]):
            col = ref[:, j]
            le = np.searchsorted(col, X[:, j], "right")
            ge = n - np.searchsorted(col, X[:, j], "left")
            p = np.minimum(1.0, 2.0 * (np.minimum(le, ge) + 1) / (n + 1))
            out[:, j] = -np.log10(p)
        return out

    def neglogp(self, X: np.ndarray, flows: np.ndarray) -> np.ndarray:
        X = np.asarray(X, np.float32)
        out = np.empty(X.shape, np.float64)
        for f in set(flows.tolist()):
            m = flows == f
            out[m] = self._neglogp(X[m], self.ref.get(f, self.ref["*"]))
        return out

    def score(self, X: np.ndarray, flows: np.ndarray) -> np.ndarray:
        nl = self.neglogp(X, flows)
        return np.sort(nl, axis=1)[:, -TOP_K:].sum(axis=1)

    def score_ceiling(self, flow: str) -> float:
        """Highest attainable score in this flow: TOP_K features outside every training value of the flow."""
        n = len(self.ref.get(flow, self.ref["*"]))
        return TOP_K * -math.log10(min(1.0, 2.0 / (n + 1)))

    def explain(self, x: np.ndarray, flow: str, k: int = 5) -> list[dict]:
        ref = self.ref.get(flow, self.ref["*"])
        nl = self._neglogp(np.asarray(x, np.float32)[None, :], ref)[0]
        order = np.argsort(-nl, kind="stable")[:k]
        med = ref[len(ref) // 2]
        return [{"feature": self.keys[j], "value": float(x[j]), "tail_p": float(10 ** -nl[j]),
                 "typical": float(med[j])} for j in order if nl[j] > 0]


class IForestModel:
    """IsolationForest on robust-standardized features (median / IQR, falling back to std, then 1; clipped at
    +-50). The flow type enters through the flow_* features."""

    def __init__(self, n_estimators=300, max_samples=2048, seed=SEED):
        self.params = dict(n_estimators=n_estimators, max_samples=max_samples, random_state=seed, n_jobs=-1)

    def _z(self, X):
        return np.clip((np.asarray(X, np.float64) - self.center) / self.scale, -50, 50)

    def fit(self, X: np.ndarray, flows=None) -> "IForestModel":
        X = np.asarray(X, np.float64)
        self.center = np.median(X, axis=0)
        q75, q25 = np.percentile(X, [75, 25], axis=0)
        sd = X.std(axis=0)
        self.scale = np.where(q75 - q25 > 0, q75 - q25, np.where(sd > 0, sd, 1.0))
        self.forest = IsolationForest(**self.params).fit(self._z(X))
        return self

    def score(self, X: np.ndarray, flows=None) -> np.ndarray:
        return -self.forest.score_samples(self._z(X))

    def score_ceiling(self, flow: str) -> float:
        """-score_samples lies in (0, 1) and has no per-flow normalization: a row isolated at the root of every tree
        approaches 1 in any flow."""
        return 1.0


CANDIDATES = {"iforest_global": IForestModel, "tail_per_flow": lambda: TailModel(ft.FEATURE_KEYS)}


# --- featurizing and the cache --------------------------------------------------------------------------------------

def featurize(txs) -> dict:
    """Arrays over an iterable of FastNEAR records: ids, month, flow, failed, source, label, campaign, role, X
    (FEATURE_KEYS order, float32), rule_sev (SEV_RANK int) and rules (list of rule names per tx)."""
    cols = {k: [] for k in ("ids", "month", "flow", "failed", "source", "label", "campaign", "role", "rules")}
    X, sev = [], []
    for tx in txs:
        m = tx.get("_meta") or {}
        f = ft.tx_features(tx)
        hits = ft.rule_hits(tx)
        cols["ids"].append(tx["transaction"]["hash"])
        cols["month"].append(m.get("month"))
        cols["flow"].append(ft.flow_type(tx))
        cols["failed"].append(any_receipt_failed(tx))
        for k in ("source", "label", "campaign", "role"):
            cols[k].append(None if m.get(k) is None else str(m.get(k)))
        cols["rules"].append(sorted({(h["rule"], h["severity"]) for h in hits}))
        X.append([f[k] for k in ft.FEATURE_KEYS])
        sev.append(SEV_RANK[max_severity([h["severity"] for h in hits])])
    out = {k: np.array(v, dtype=object) for k, v in cols.items() if k != "rules"}
    out["rules"] = cols["rules"]
    out["failed"] = np.array(cols["failed"], bool)
    out["X"] = np.array(X, np.float32).reshape(-1, len(ft.FEATURE_KEYS))
    out["rule_sev"] = np.array(sev, np.int8)
    return out


def build_cache(path=CACHE) -> dict:
    t0 = time.time()
    cache = {"normals": featurize(iter_jsonl_gz(NORMALS)), "labelled": featurize(iter_jsonl_gz(LABELLED)),
             "feature_keys": list(ft.FEATURE_KEYS), "code_sha256": code_hashes(),
             "normals_sha256": sha256_file(NORMALS), "labelled_sha256": sha256_file(LABELLED), "built_at": utc_now()}
    with open(path, "wb") as f:
        pickle.dump(cache, f, protocol=pickle.HIGHEST_PROTOCOL)
    print(f"cached {len(cache['normals']['ids'])} normals and {len(cache['labelled']['ids'])} labelled "
          f"in {time.time() - t0:.0f}s -> {path}")
    return cache


def load_cache(path=CACHE) -> dict:
    """The feature cache, refused if the feature code or the data files changed since it was built."""
    with open(path, "rb") as f:
        cache = pickle.load(f)
    feat = "near/intents/features.py"
    if cache["code_sha256"][feat] != sha256_file(ROOT / feat):
        raise ValueError(f"{path}: built with a different {feat}; rerun `model cache`")
    if cache["feature_keys"] != list(ft.FEATURE_KEYS):
        raise ValueError(f"{path}: FEATURE_KEYS changed; rerun `model cache`")
    return cache


def split_masks(month: np.ndarray) -> dict[str, np.ndarray]:
    month = month.astype(str)
    return {"train": month <= TRAIN_LAST, "calib": (month >= CALIB_FIRST) & (month <= CALIB_LAST),
            "test": month >= TEST_FIRST}


# --- artifact ---------------------------------------------------------------------------------------------------------

def build_artifact(kind: str, model, tail: TailModel, train_scores: np.ndarray, thresholds: dict,
                   train_ids: list[str], extra: dict | None = None) -> dict:
    """Everything score_tx needs. train_scores give the anomaly percentile; tail explains top features."""
    sorted_scores = np.sort(np.asarray(train_scores, np.float64))
    art = {"version": TAG, "kind": kind, "model": model, "tail": tail, "train_scores": sorted_scores,
           "thresholds": {k: float(v) for k, v in thresholds.items()}, "feature_keys": list(ft.FEATURE_KEYS),
           "train_ids": sorted(train_ids)}
    art["severity_weight"] = {"high": 1.0, "medium": percentile(art, thresholds["medium"]), "low": 0.0}
    art.update(extra or {})
    return art


def percentile(art: dict, score: float) -> float:
    """Share of training normals scoring strictly below this score."""
    ts = art["train_scores"]
    return float(np.searchsorted(ts, score, "left") / len(ts))


def save_artifact(art: dict, out_dir, tag: str = TAG, meta: dict | None = None, root=ROOT) -> Path:
    """Write {tag}.pkl, {tag}.train_ids.json and the manifest {tag}.json (meta, thresholds, sha256 of the pkl, the
    code files and the train ids); returns the pkl path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pkl = out_dir / f"{tag}.pkl"
    with open(pkl, "wb") as f:
        pickle.dump(art, f, protocol=pickle.HIGHEST_PROTOCOL)
    ids_path = out_dir / f"{tag}.train_ids.json"
    ids_path.write_text(json.dumps(art["train_ids"]))
    man = dict(meta or {}, version=art["version"], kind=art["kind"], thresholds=art["thresholds"],
               severity_weight=art["severity_weight"], frozen_at=utc_now(), pkl_sha256=sha256_file(pkl),
               code_sha256=code_hashes(root), train_ids_file=ids_path.name,
               train_ids_sha256=sha256_json(art["train_ids"]), n_train=len(art["train_ids"]))
    pkl.with_suffix(".json").write_text(json.dumps(man, indent=1))
    return pkl


def load_artifact(pkl=OUT / f"{TAG}.pkl", root=ROOT) -> dict:
    """Load a frozen artifact after checking the pkl, the feature/model code and the train ids against its manifest."""
    pkl = Path(pkl)
    man = json.loads(pkl.with_suffix(".json").read_text())
    if sha256_file(pkl) != man["pkl_sha256"]:
        raise ValueError(f"{pkl.name}: pkl sha256 does not match its manifest")
    now = code_hashes(root)
    for f, h in man["code_sha256"].items():
        if now.get(f) != h:
            raise ValueError(f"{f} changed since {pkl.name} was frozen; refreeze")
    with open(pkl, "rb") as f:
        art = pickle.load(f)
    if sha256_json(art["train_ids"]) != man["train_ids_sha256"]:
        raise ValueError(f"{pkl.name}: train ids do not match the manifest")
    return art


# --- prediction -----------------------------------------------------------------------------------------------------

_LOADED: dict = {}


def default_artifact() -> dict:
    if "art" not in _LOADED:
        _LOADED["art"] = load_artifact()
    return _LOADED["art"]


def score_matrix(art: dict, X: np.ndarray, flows: np.ndarray) -> np.ndarray:
    return art["model"].score(X, flows)


def score_tx(tx: dict, art: dict | None = None, intents_ids=None) -> dict:
    """Score one FastNEAR or RPC transaction: {risk, label, rule_hits, top_features, anomaly_score,
    anomaly_percentile, flow}."""
    art = art or default_artifact()
    f = ft.tx_features(tx, intents_ids)
    hits = ft.rule_hits(tx, intents_ids)
    flow = ft.flow_type(tx, intents_ids)
    x = np.array([[f[k] for k in art["feature_keys"]]], np.float32)
    s = float(score_matrix(art, x, np.array([flow]))[0])
    pct = percentile(art, s)
    sev = max_severity([h["severity"] for h in hits])
    w = art["severity_weight"].get(sev, 0.0) if sev else 0.0
    return {"risk": round(max(w, pct), 6), "label": label_for(sev, s, art["thresholds"]), "rule_hits": hits,
            "top_features": art["tail"].explain(x[0], flow, k=5), "anomaly_score": s, "anomaly_percentile": pct,
            "flow": flow}


# --- freeze -----------------------------------------------------------------------------------------------------------

def calibrate(scores: np.ndarray, rule_sev: np.ndarray) -> dict:
    """Combined thresholds (rules first) and anomaly-only thresholds on calibration rows."""
    hi = alert_threshold(scores, rule_sev >= 3, HIGH_RATE)
    med = min(alert_threshold(scores, rule_sev >= 2, MEDIUM_RATE), hi)
    hi_a = alert_threshold(scores, np.zeros(len(scores), bool), HIGH_RATE)
    med_a = min(alert_threshold(scores, np.zeros(len(scores), bool), MEDIUM_RATE), hi_a)
    return {"combined": {"high": hi, "medium": med}, "anomaly_only": {"high": hi_a, "medium": med_a}}


def freeze(cache_path=CACHE, out_dir=OUT) -> dict:
    cache = load_cache(cache_path)
    N = cache["normals"]
    sp = split_masks(N["month"])
    Xtr, ftr = N["X"][sp["train"]], N["flow"][sp["train"]].astype(str)
    Xca, fca = N["X"][sp["calib"]], N["flow"][sp["calib"]].astype(str)
    sev_ca, fail_ca = N["rule_sev"][sp["calib"]], N["failed"][sp["calib"]]
    print(f"train {len(Xtr)}  calib {len(Xca)}  test {int(sp['test'].sum())} (test untouched)")

    report = {"decision_rule": DECISION_RULE, "selection_note": SELECTION_NOTE, "candidates": {}}
    fitted = {}
    for name, make in CANDIDATES.items():
        t0 = time.time()
        m = make().fit(Xtr, ftr)
        s_tr, s_ca = m.score(Xtr, ftr), m.score(Xca, fca)
        tmp = {"train_scores": np.sort(s_tr)}
        pct_ca = np.searchsorted(tmp["train_scores"], s_ca, "left") / len(s_tr)
        thr = calibrate(s_ca, sev_ca)
        lab = labels_for(sev_ca, s_ca, thr["combined"])
        fitted[name] = (m, s_tr, s_ca, thr)
        report["candidates"][name] = {
            "fit_score_s": round(time.time() - t0, 1),
            "failing_calib_mean_pct": float(pct_ca[fail_ca].mean()),
            "nonfailing_calib_mean_pct": float(pct_ca[~fail_ca].mean()),
            "failing_calib_medium_plus": int(np.isin(lab[fail_ca], ["medium", "high"]).sum()),
            "n_failing_calib": int(fail_ca.sum()),
            "calib_high": int((lab == "high").sum()), "calib_medium_plus": int(np.isin(lab, ["medium", "high"]).sum()),
            "thresholds": thr,
            "score_ceiling_by_flow": {f: m.score_ceiling(f) for f in sorted(set(ftr.tolist()))},
        }
        c = report["candidates"][name]
        c["eligible"] = all(v >= thr["combined"]["medium"] for v in c["score_ceiling_by_flow"].values())
        print(name, json.dumps(report["candidates"][name]))
    a, b = (report["candidates"][k] for k in ("iforest_global", "tail_per_flow"))
    eligible = [k for k, c in report["candidates"].items() if c["eligible"]]
    if len(eligible) == 1:
        pick = eligible[0]
        why = "the only eligible candidate (score ceiling reaches the medium threshold in every flow)"
    elif not eligible:
        raise SystemExit("no eligible candidate")
    elif abs(a["failing_calib_mean_pct"] - b["failing_calib_mean_pct"]) >= 0.005:
        pick = min(report["candidates"], key=lambda k: report["candidates"][k]["failing_calib_mean_pct"])
        why = "lower mean percentile on failing calibration normals"
    elif a["failing_calib_medium_plus"] != b["failing_calib_medium_plus"]:
        pick = min(report["candidates"], key=lambda k: report["candidates"][k]["failing_calib_medium_plus"])
        why = "tie on mean percentile; fewer failing calibration normals at medium+"
    else:
        pick, why = "tail_per_flow", "tie on both; interpretable default"
    report.update(pick=pick, why=why)
    print(f"pick {pick}: {why}")

    m, s_tr, s_ca, thr = fitted[pick]
    tail = m if isinstance(m, TailModel) else TailModel(ft.FEATURE_KEYS).fit(Xtr, ftr)
    train_ids = N["ids"][sp["train"]].tolist()
    art = build_artifact(pick, m, tail, s_tr, thr["combined"], train_ids,
                         extra={"thresholds_anomaly_only": thr["anomaly_only"]})
    split = {"train_last": TRAIN_LAST, "calib": [CALIB_FIRST, CALIB_LAST], "test_first": TEST_FIRST,
             "n_train": int(sp["train"].sum()), "n_calib": int(sp["calib"].sum()), "n_test": int(sp["test"].sum()),
             "train_by_flow": dict(Counter(ftr.tolist())), "calib_by_flow": dict(Counter(fca.tolist()))}
    meta = {"decision": report, "split": split, "rates": {"high": HIGH_RATE, "medium": MEDIUM_RATE},
            "thresholds_anomaly_only": thr["anomaly_only"], "normals_sha256": cache["normals_sha256"],
            "calib_percentile_at_thresholds": {k: percentile(art, v) for k, v in thr["combined"].items()}}
    pkl = save_artifact(art, out_dir, TAG, meta)
    print(f"froze {pkl} ({pkl.stat().st_size / 1e6:.1f} MB)")
    return meta


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("stage", choices=["cache", "freeze"])
    a = ap.parse_args(argv)
    if a.stage == "cache":
        build_cache()
    else:
        freeze()


if __name__ == "__main__":
    # Run through the importable module so pickled classes resolve as near.intents.model.*, not __main__.*.
    from near.intents import model as _model

    _model.main()
