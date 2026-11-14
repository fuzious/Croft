"""Code risk from a frozen NEAR model, used by near.service.

    score_functions(fns) -> [{fn, path, impl, start_line, risk, label, vuln_class_guess, detector_hits, ...}]
    score_source(files)  -> {risk, label, top, functions, n_functions, thresholds, model: {version, sha256}}

Model: `frozen_near_v2` by default when its LLM checkpoint is present, else `frozen_near_v1`; NEAR_ORACLE_MODEL picks one.
The model loads once, lazily, and refuses to load if the pickle, the feature code or (v2) the LLM checkpoint
differs from its frozen manifest.

v1 (near.model.freeze): risk = HGB probability on analyzer features of the function text + hashed code tokens.
v2 (near.model.freeze_v2): an ensemble of two models, risk = mean of the two models' rank percentiles, each against
its own held-out training-score distribution:
- classical v2: HGB on analyzer features computed with the function's file, per-detector counts, file / Cargo.toml
  context (near.model.context) and code tokens (near.model.train_classic_v2.matrices_for_source);
- the code LLM: Qwen2.5-Coder-0.5B fine-tuned with LoRA, merged (near/models/llm_final, near.model.llm_classifier).
In score_source the LLM runs only on the functions that count toward the contract (public, non-test, non-trivial,
contract code); other non-trivial functions get `classical_risk` only and `risk` None, since they cannot change the
verdict. score_functions runs both models on every non-trivial function it is given.

Labels: high / medium / low at the frozen block / warn thresholds (1% / 5% FPR on contract-code corpus functions in
held-out training scores). Contract risk = max over its counted functions. Trivial functions (< 2 statements or a
body under 3 lines) are not scored by the model: the corpus negatives exclude them, so the model never saw a safe one
(detector hits are still reported).
"""
from __future__ import annotations

import hashlib
import json
import os
import pickle
from glob import glob
from pathlib import Path

import numpy as np
import scipy.sparse as sp

from near.analyzer import detect, extract_functions
from near.collect.extract_corpus import is_trivial
from near.model import featurize as fz
from near.model.eval_common import is_contract_code
from near.model.train_classic import predict_model

ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = ROOT / "near" / "models"
MODEL_NAMES = ("frozen_near_v2", "frozen_near_v1")
DEFAULT_MODEL = "frozen_near_v2"
FROZEN_V1 = MODELS_DIR / "frozen_near_v1.pkl"
LLM_FILES = ("config.json", "model.safetensors", "oracle.json", "tokenizer.json", "tokenizer_config.json")
TOP_N = 10
_CACHE: dict = {}


class FrozenModelError(RuntimeError):
    pass


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def selected_model(env=None, root=ROOT) -> str:
    """The frozen model this process serves: $NEAR_ORACLE_MODEL; unset, frozen_near_v2 when its LLM checkpoint is
    unpacked (archives/near_llm_v2.zip, ~0.9 GB), else frozen_near_v1."""
    name = (os.environ if env is None else env).get("NEAR_ORACLE_MODEL")
    if not name:
        try:
            llm_dir = json.loads((Path(root) / "near/models/frozen_near_v2.json").read_text())["llm_dir"]
        except (OSError, ValueError, KeyError):
            llm_dir = None
        has_llm = llm_dir and (Path(root) / llm_dir / "model.safetensors").exists()
        name = DEFAULT_MODEL if has_llm else "frozen_near_v1"
    if name not in MODEL_NAMES:
        raise FrozenModelError(f"NEAR_ORACLE_MODEL={name!r}: expected one of {MODEL_NAMES}")
    return name


def code_files(kind: str = "v1") -> list[str]:
    """Code that defines the model's inputs and scoring: analyzer (not its tests), featurize, the estimator code;
    for v2 also the file context, the v2 matrices and the LLM's input / scoring code."""
    files = sorted(p for p in glob("near/analyzer/*.py", root_dir=ROOT) if not Path(p).name.startswith("test_"))
    files += ["near/collect/extract_corpus.py", "near/model/featurize.py"]
    if kind == "v1":
        return files + ["near/model/train_classic.py"]
    return files + ["near/model/context.py", "near/model/train_classic_v2.py", "near/model/encoder.py",
                    "near/model/llm_classifier.py"]


def code_hashes(kind: str = "v1") -> dict[str, str]:
    return {f: sha256_file(ROOT / f) for f in code_files(kind)}


def llm_hashes(llm_dir) -> dict[str, str]:
    return {f: sha256_file(Path(llm_dir) / f) for f in LLM_FILES}


def manifest_path(pkl) -> Path:
    return Path(pkl).with_suffix(".json")


def _model_info(pkl) -> dict | None:
    try:
        m = json.loads(manifest_path(pkl).read_text())
    except (OSError, ValueError):
        return None
    return {"version": m["version"], "sha256": m["pkl_sha256"]}


try:
    FROZEN = MODELS_DIR / f"{selected_model()}.pkl"
except FrozenModelError:  # a bad NEAR_ORACLE_MODEL: load() raises, and the service falls back to detectors
    FROZEN = MODELS_DIR / "NEAR_ORACLE_MODEL_invalid.pkl"
MODEL_INFO = _model_info(FROZEN)


def load(pkl=None, cache: bool = True) -> dict:
    """The frozen artifact {estimator, class_head, thresholds, version, ...} (v1) or {kind: ensemble_v2, classical,
    llm_dir, ref_classical, ref_llm, thresholds, ...} (v2); checked against its manifest."""
    if pkl is None:
        pkl = MODELS_DIR / f"{selected_model()}.pkl"
    key = str(pkl)
    if cache and key in _CACHE:
        return _CACHE[key]
    try:
        man = json.loads(manifest_path(pkl).read_text())
    except (OSError, ValueError) as e:
        raise FrozenModelError(f"no frozen model manifest next to {pkl}: {e}") from e
    if sha256_file(pkl) != man["pkl_sha256"]:
        raise FrozenModelError(f"{pkl} sha256 differs from its manifest")
    kind = man.get("code_kind", "v1")
    changed = sorted(f for f, h in code_hashes(kind).items() if man["code_sha256"].get(f) != h)
    changed += sorted(set(man["code_sha256"]) - set(code_files(kind)))
    if changed:
        raise FrozenModelError(f"feature code changed since the freeze: {changed}")
    if man.get("llm_sha256"):
        llm_dir = ROOT / man["llm_dir"]
        try:
            bad = sorted(f for f, h in llm_hashes(llm_dir).items() if man["llm_sha256"].get(f) != h)
        except OSError as e:
            raise FrozenModelError(f"LLM checkpoint {llm_dir} unreadable: {e}") from e
        if bad:
            raise FrozenModelError(f"LLM checkpoint {llm_dir} differs from the freeze: {bad}")
    with open(pkl, "rb") as f:
        art = pickle.load(f)
    art["info"] = {"version": man["version"], "sha256": man["pkl_sha256"]}
    if cache:
        _CACHE[key] = art
    return art


def _llm(art: dict):
    """The merged LLM of a v2 artifact (model, tokenizer, meta), loaded once per process on MPS or CPU."""
    key = ("llm", str(art["llm_dir"]))
    if key not in _CACHE:
        from transformers.utils import logging as hf_logging

        from near.model import llm_classifier
        hf_logging.disable_progress_bar()
        _CACHE[key] = llm_classifier.load_final(ROOT / art["llm_dir"])
    return _CACHE[key]


def percentile(ref: np.ndarray, x: np.ndarray) -> np.ndarray:
    """Mid-rank of x in the sorted reference scores, in [0, 1] (ties count half, as scipy rankdata average / n)."""
    ref = np.asarray(ref)
    return (np.searchsorted(ref, x, "left") + np.searchsorted(ref, x, "right")) / (2.0 * len(ref))


def ensemble_risk(art: dict, s_classical: np.ndarray, s_llm: np.ndarray) -> np.ndarray:
    return (percentile(art["ref_classical"], s_classical) + percentile(art["ref_llm"], s_llm)) / 2


def risk_label(risk: float, thresholds: dict) -> str:
    return "high" if risk >= thresholds["block"] else "medium" if risk >= thresholds["warn"] else "low"


def model_scored(fn: dict) -> bool:
    """Trivial functions (< 2 statements or body < 3 lines, near.collect.extract_corpus) are not scored: the corpus
    negatives contain none, so the model would read any one-line getter as a mutation."""
    return not is_trivial(fn.get("code") or "")


def counts_toward_contract(fn: dict) -> bool:
    """The contract-level aggregation set: model-scored, public, non-test, contract-code functions."""
    return bool(fn.get("is_public")) and model_scored(fn) and is_contract_code({"code": fn.get("code") or "", "path": fn.get("path") or "",
                                                           "is_test": fn.get("is_test")})


def matrices(fns: list[dict]):
    """(analyzer features, token hashes) exactly as near.model.featurize builds them for training rows."""
    A = fz.analyzer_matrix(fns, workers=1)
    T = fz.TOKEN_HASH.transform([fz.token_ngrams(f) for f in fns]).astype(np.float32)
    return A, T


def class_guess(head: dict, A, T) -> tuple[list[str], np.ndarray]:
    X = sp.hstack([sp.csr_matrix(A / head["amax"]), T], format="csr")
    p = head["clf"].predict_proba(X)
    return [str(c) for c in head["clf"].classes_[p.argmax(axis=1)]], p.max(axis=1)


def pseudo_files(fns: list[dict]) -> dict[str, str]:
    """When no source files are given: each path's file = its given functions joined, so the v2 context sees them
    (a missing file would put the functions outside what the model was trained on)."""
    out: dict[str, list[str]] = {}
    for f in fns:
        out.setdefault(f.get("path") or "", []).append(f.get("code") or "")
    return {p: "\n\n".join(c) for p, c in out.items()}


def _predict_v1(art: dict, fns: list[dict], scored: list[int]) -> dict:
    A, T = matrices([fns[i] for i in scored])
    risk = predict_model(art["estimator"], A, T, None)
    guess, conf = class_guess(art["class_head"], A, T)
    return {i: (float(r), g, float(c), {}) for i, r, g, c in zip(scored, risk, guess, conf)}


def _predict_v2(art: dict, fns: list[dict], scored: list[int], llm_scope, files) -> dict:
    from near.model import train_classic_v2 as tc2
    sub = [fns[i] for i in scored]
    M = tc2.matrices_for_source(files or pseudo_files(fns), sub)
    s_c = tc2.predict_model(art["classical"]["estimator"], M)
    guess, conf = class_guess_v2(art["classical"]["class_head"], art["classical"]["estimator"], M)
    run = [k for k, i in enumerate(scored) if llm_scope is None or llm_scope[i]]
    s_l = np.full(len(scored), np.nan)
    if run:
        from near.model import llm_classifier
        s_l[run] = llm_classifier.score_rows([sub[k] for k in run], _llm(art))
    ens = np.full(len(scored), np.nan)
    ens[run] = ensemble_risk(art, s_c[run], s_l[run])
    return {i: (None if np.isnan(ens[k]) else float(ens[k]), guess[k], float(conf[k]),
                {"classical_risk": round(float(s_c[k]), 6),
                 "llm_risk": None if np.isnan(s_l[k]) else round(float(s_l[k]), 6)})
            for k, i in enumerate(scored)}


def class_guess_v2(head: dict, est: dict, M: dict) -> tuple[list[str], np.ndarray]:
    """vuln_class head of v2: multinomial LR on the classical design matrix (dense blocks / max-abs + tokens)."""
    p = head["clf"].predict_proba(head_matrix(head, est, M))
    return [str(c) for c in head["clf"].classes_[p.argmax(axis=1)]], p.max(axis=1)


def head_matrix(head: dict, est: dict, M: dict) -> sp.csr_matrix:
    dense = np.hstack([M[b] for b in est["blocks"] if b != "T"])
    return sp.hstack([sp.csr_matrix(dense / head["amax"]), M["T"]], format="csr")


def score_functions(fns: list[dict], art: dict | None = None, file_src: dict[str, str] | None = None,
                    llm_scope: list[bool] | None = None) -> list[dict]:
    """Per-function risk, label, vuln_class guess (multinomial head on label-1 rows) and detector hits; trivial
    functions get risk / label / guess None (detector hits only). v2: file_src gives the files for the file context
    (else each path's given functions); llm_scope (one bool per fn) limits where the LLM runs, the others get
    `classical_risk` only and risk None."""
    if not fns:
        return []
    art = art or load()
    scored = [i for i, f in enumerate(fns) if model_scored(f)]
    pred = {}
    if scored:
        pred = (_predict_v2(art, fns, scored, llm_scope, file_src) if art.get("kind") == "ensemble_v2"
                else _predict_v1(art, fns, scored))
    out = []
    for i, f in enumerate(fns):
        r, g, c, extra = pred.get(i, (None, None, None, {}))
        src = (file_src or {}).get(f.get("path"))
        out.append({"path": f.get("path"), "fn": f.get("fn"), "impl": f.get("impl"), "start_line": f.get("start_line"),
                    "is_near_bindgen": f.get("is_near_bindgen"), "is_public": f.get("is_public"),
                    "model_scored": r is not None, "risk": None if r is None else round(r, 6),
                    "label": None if r is None else risk_label(r, art["thresholds"]),
                    "vuln_class_guess": g, "vuln_class_confidence": None if c is None else round(c, 4),
                    **extra, "detector_hits": detect(f, src), "counts_toward_contract": counts_toward_contract(f)})
    return out


def score_source(files: dict[str, str], art: dict | None = None) -> dict:
    """Contract risk = max over counted functions (test functions are skipped entirely)."""
    art = art or load()
    fns = [f for path, src in sorted(files.items()) for f in extract_functions(src, path) if not f.get("is_test")]
    scored = score_functions(fns, art, files, llm_scope=[counts_toward_contract(f) for f in fns])
    counted = sorted((s for s in scored if s["counts_toward_contract"]), key=lambda s: (-s["risk"], s["path"] or "",
                                                                                         s["start_line"] or 0))
    risk = counted[0]["risk"] if counted else 0.0
    return {"risk": risk, "label": risk_label(risk, art["thresholds"]), "top": counted[:TOP_N], "functions": scored,
            "n_functions": len(scored), "n_counted": len(counted), "thresholds": art["thresholds"],
            "model": art.get("info") or {"version": art["version"], "sha256": None}}
