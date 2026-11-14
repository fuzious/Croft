"""NEAR security oracle API (`uvicorn near.service.app:app`).

POST /v1/check    {receiver_id, agent_id?, method?, deposit_yocto?, source_files?} -> verdict allow|warn|block
POST /v1/analyze  {source_files} -> contract risk and per-function risk
POST /v1/report   {account_id, evidence_url, evidence_sha256?, reporter?, note?, confirm?} -> local blocklist
POST /v1/intents/score {tx_hash, sender_id?} -> NEAR Intents transaction risk, label and rule hits (FastNEAR, mainnet)
GET  /v1/health
GET  /demo/      browser demo (near/demo/index.html)

Config (env): NEAR_NETWORK (mainnet|testnet|sandbox), NEAR_RPC_URL, ORACLE_CONTRACT_ID, NEARBLOCKS_API,
NEARBLOCKS_API_KEY, ORACLE_BLOCKLIST_PATH, ORACLE_ADMIN_TOKEN (needed to confirm a report through the API)."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from near.analyzer import detect, extract_functions
from near.analyzer.detectors import SEVERITY

from . import blocklist, intents, policy, signals, source
from .policy import THRESHOLDS
from .signals import sig

ACCOUNT_ID = r"^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$"
MAX_SOURCE_FILES = 2000
MAX_SOURCE_BYTES = 5 * 1024 * 1024
MAX_FILE_BYTES = source.MAX_FILE_BYTES
MAX_BODY_BYTES = 6 * 1024 * 1024
INTENTS_DEADLINE_S = 15.0   # /v1/check waits at most this long, from its start, for the intents_activity signal
DETECTORS_SHA256 = hashlib.sha256(
    (Path(__file__).resolve().parents[1] / "analyzer" / "detectors.py").read_bytes()).hexdigest()
CFG = signals.load_config()
app = FastAPI(title="NEAR Security Oracle", version="1")


@app.middleware("http")
async def refuse_large_bodies(request: Request, call_next):
    """Refuse a declared body over MAX_BODY_BYTES before it is read and parsed."""
    try:
        size = int(request.headers.get("content-length") or 0)
    except ValueError:
        size = 0
    if size > MAX_BODY_BYTES:
        return JSONResponse({"detail": f"request body is limited to {MAX_BODY_BYTES // 2**20} MB"}, status_code=413)
    return await call_next(request)


app.mount("/demo", StaticFiles(directory=Path(__file__).resolve().parents[1] / "demo", html=True), name="demo")
_risk_cache: dict = {}


class CheckRequest(BaseModel):
    receiver_id: str = Field(min_length=2, max_length=64, pattern=ACCOUNT_ID)
    agent_id: Optional[str] = Field(None, min_length=2, max_length=64, pattern=ACCOUNT_ID)
    method: Optional[str] = Field(None, max_length=256)
    deposit_yocto: Optional[str] = Field(None, pattern=r"^\d{1,40}$")
    source_files: Optional[dict[str, str]] = None


class IntentsScoreRequest(BaseModel):
    tx_hash: str = Field(min_length=32, max_length=44)
    sender_id: Optional[str] = Field(None, min_length=2, max_length=64, pattern=ACCOUNT_ID)

    @field_validator("tx_hash")
    @classmethod
    def _base58_32_bytes(cls, v: str) -> str:
        if not intents.valid_tx_hash(v):
            raise ValueError("tx_hash must be a base58-encoded 32-byte NEAR transaction hash")
        return v


class AnalyzeRequest(BaseModel):
    source_files: dict[str, str]


class ReportRequest(BaseModel):
    account_id: str = Field(min_length=2, max_length=64, pattern=ACCOUNT_ID)
    evidence_url: str = Field(max_length=512, pattern=r"^https?://\S+$")
    evidence_sha256: Optional[str] = Field(None, pattern=r"^[0-9a-f]{64}$")
    reporter: Optional[str] = Field(None, max_length=64)
    note: Optional[str] = Field(None, max_length=1000)
    confirm: bool = False


# ---- code risk ------------------------------------------------------------------------------------------------
def detector_risk(hits: list[dict]) -> float:
    """Noisy-or of severity weights over one function's detector hits."""
    p = 1.0
    for h in hits:
        p *= 1 - THRESHOLDS["detector_weight"].get(h.get("severity"), 0.0)
    return round(1 - p, 4)


def detectors_only_label(risk: float) -> str:
    label = policy.risk_label(risk)
    return "medium" if label == "high" and not THRESHOLDS["detectors_only_can_block"] else label


def function_rows(files: dict[str, str]) -> list[dict]:
    """One row per non-test function with its detector hits and detector risk."""
    rows = []
    for path, src in sorted(files.items()):
        for fn in extract_functions(src, path):
            if fn.get("is_test"):
                continue
            hits = detect(fn, src)
            worst = max(hits, key=lambda h: SEVERITY.get(h.get("severity"), 0), default=None)
            rows.append({"path": path, "fn": fn["fn"], "impl": fn.get("impl"), "start_line": fn.get("start_line"),
                         "is_near_bindgen": fn.get("is_near_bindgen"), "is_public": fn.get("is_public"),
                         "risk": detector_risk(hits), "vuln_class_guess": worst and worst["vuln_class"],
                         "detector_hits": hits})
    return rows


def code_risk(files: dict[str, str]) -> dict:
    """{risk, label, top, functions, n_functions, version, sha256[, fallback_reason]} for a contract's source.
    The one place that picks the scorer: the frozen model through near.model.predict.score_source when it loads
    and scores, else the analyzer detectors (version "detectors-only", sha256 of detectors.py)."""
    key = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    if key in _risk_cache:
        return _risk_cache[key]
    why = None
    try:
        from near.model import predict
        res = predict.score_source(files)
        info = res.get("model") or getattr(predict, "MODEL_INFO", None) or {}
        top = res.get("top") or []
        out = {"risk": round(float(res["risk"]), 4), "label": res["label"], "top": top[:10],
               "functions": res.get("functions") or top, "n_functions": res.get("n_functions", len(top)),
               "version": info.get("version", "near-model"), "sha256": info.get("sha256")}
    except Exception as e:  # no model package or no frozen model yet: fall back, and say why
        why = f"{type(e).__name__}: {e}"
        rows = function_rows(files)
        risk = max((r["risk"] for r in rows), default=0.0)
        top = sorted((r for r in rows if r["risk"] > 0), key=lambda r: (-r["risk"], r["path"], r["start_line"]))
        out = {"risk": risk, "label": detectors_only_label(risk), "top": top[:10], "functions": rows,
               "n_functions": len(rows), "version": "detectors-only", "sha256": DETECTORS_SHA256,
               "fallback_reason": why}
    if len(_risk_cache) > 256:
        _risk_cache.clear()
    _risk_cache[key] = out
    return out


def _check_files(files: dict[str, str]) -> None:
    sizes = [len(s.encode("utf-8")) for s in files.values()]
    if (len(files) > MAX_SOURCE_FILES or sum(sizes) > MAX_SOURCE_BYTES
            or any(size > MAX_FILE_BYTES for size in sizes)):
        raise HTTPException(413, f"source_files is limited to {MAX_SOURCE_FILES} files, "
                                 f"{MAX_FILE_BYTES // 1024} KB per file and {MAX_SOURCE_BYTES // 2**20} MB in all")


_BRIEF_FN_KEYS = ("path", "fn", "start_line", "risk", "label", "vuln_class_guess", "is_public", "model_scored")


def _brief_fn(f: dict) -> dict:
    return {k: f.get(k) for k in _BRIEF_FN_KEYS} | {
        "detector_hits": [{k: h.get(k) for k in ("detector", "severity")} for h in f.get("detector_hits") or []]}


def _brief(cr: dict) -> dict:
    """The code_risk signal: top functions, plus the public functions the model did not score that have detector
    hits (near.service.policy warns on a high-severity one)."""
    unscored = [f for f in cr.get("functions") or [] if f.get("is_public") and not f.get("model_scored")
                and f.get("detector_hits")]
    return {k: cr[k] for k in ("risk", "label", "version", "n_functions")} | {
        "top": [_brief_fn(t) for t in cr["top"][:5]], "functions": [_brief_fn(f) for f in unscored[:20]]}


# ---- endpoints ------------------------------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/demo/")


@app.get("/v1/health")
def health():
    cr = code_risk({"probe.rs": "fn probe() {}"})
    return {"status": "ok", "network": CFG["network"], "rpc_hosts": [urlsplit(u).hostname for u in CFG["rpc_urls"]],
            "oracle_contract_id": CFG["oracle_contract_id"], "nearblocks_api": CFG["nearblocks_api"],
            "model": {"version": cr["version"], "sha256": cr["sha256"], "fallback_reason": cr.get("fallback_reason")}}


@app.post("/v1/analyze")
def analyze(req: AnalyzeRequest):
    _check_files(req.source_files)
    cr = code_risk(req.source_files)
    return {"risk": cr["risk"], "label": cr["label"], "n_functions": cr["n_functions"], "top": cr["top"],
            "functions": cr["functions"], "model": {"version": cr["version"], "sha256": cr["sha256"]}}


def _intents_activity(receiver_id: str) -> dict:
    if CFG["network"] != "mainnet":
        return sig(None, f"n/a: FastNEAR indexes mainnet only (network {CFG['network']})")
    return intents.activity_signal(receiver_id)


@app.post("/v1/check")
def check(req: CheckRequest):
    if req.source_files is not None:
        _check_files(req.source_files)
    now = time.time_ns()
    deadline = time.monotonic() + INTENTS_DEADLINE_S
    pool = ThreadPoolExecutor(1)   # FastNEAR in parallel with RPC and NearBlocks
    try:
        ia = pool.submit(_intents_activity, req.receiver_id)
        s = signals.account_signals(CFG, req.receiver_id, req.agent_id, now)
        try:
            s["intents_activity"] = ia.result(timeout=max(0.0, deadline - time.monotonic()))
        except TimeoutError:
            s["intents_activity"] = sig(None, intents.SOURCE, False,
                                        f"FastNEAR timed out after {INTENTS_DEADLINE_S:g} s")
    finally:
        # A timed-out read goes on in the background until it ends: at most intents_max_requests FastNEAR
        # requests of at most intents.TIMEOUT_S each (18 s from the check's start with the defaults).
        pool.shutdown(wait=False)
    try:
        s["local_blocklist"] = sig(blocklist.lookup(req.receiver_id), "local blocklist")
    except (OSError, ValueError) as e:
        s["local_blocklist"] = sig(None, "local blocklist", False, f"{type(e).__name__}: {e}")

    is_contract = s["is_contract"]["value"] if s["is_contract"]["available"] else None
    files = {}
    if req.source_files:
        files = req.source_files
        s["source"] = sig({"origin": "caller", "verified": False, "files": len(files)}, "request.source_files")
    elif is_contract:
        cs = source.contract_source(CFG, req.receiver_id)
        files = cs.pop("files")
        s["source"] = sig({**cs, "files": len(files)}, "rpc:contract_source_metadata + github tarball")
    else:
        s["source"] = sig(None, "n/a: no contract code" if is_contract is False else "contract status unknown",
                          is_contract is False, None if is_contract is False else "contract status unknown")
    if files:
        cr = code_risk(files)
        s["code_risk"] = sig(_brief(cr), cr["version"])
    else:
        cr = code_risk({"probe.rs": "fn probe() {}"})
        s["code_risk"] = (sig(None, "n/a: no contract code") if is_contract is False else
                          sig(None, "code risk", False, "no source to score"))
    d = policy.decide(s, req.deposit_yocto, CFG["network"], now)
    return {"verdict": d["verdict"], "score": d["score"], "reasons": d["reasons"], "receiver_id": req.receiver_id,
            "network": CFG["network"], "signals": s,
            "model": {"version": cr["version"], "sha256": cr["sha256"]}}


@app.post("/v1/intents/score")
def intents_score(req: IntentsScoreRequest):
    """One FastNEAR request, so the endpoint answers within intents.TIMEOUT_S; a FastNEAR timeout is a 504."""
    try:
        info = intents.model_info()
        out = intents.score_hash(req.tx_hash, req.sender_id)
    except intents.FastNearTimeout as e:
        raise HTTPException(504, str(e)) from None
    except (intents.FastNearError, intents.TxUnscorable) as e:
        raise HTTPException(502, str(e)) from None
    except intents.TxNotFound as e:
        raise HTTPException(404, str(e)) from None
    except intents.ModelUnavailable as e:   # frozen model missing or refused by its hash checks
        raise HTTPException(503, str(e)) from None
    return out | {"model": info}


@app.post("/v1/report")
def report(req: ReportRequest, authorization: Optional[str] = Header(None)):
    if req.confirm:
        token = os.environ.get("ORACLE_ADMIN_TOKEN")
        if not token or not hmac.compare_digest((authorization or "").encode(), f"Bearer {token}".encode()):
            raise HTTPException(403, "confirming a report needs the operator token (ORACLE_ADMIN_TOKEN)")
    r = blocklist.add_report(req.account_id, req.evidence_url, req.evidence_sha256, req.reporter, req.note,
                             confirmed=req.confirm)
    return {"report": r, "blocked": blocklist.lookup(req.account_id)["blocked"]}
