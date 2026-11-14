"""Oracle decision: signals -> allow | warn | block, with short reasons tied to signal values. Deterministic.

`block` if blocklisted (local confirmed report, on-chain oracle) or code risk is high and a high-severity detector hit
agrees on one of the high-risk functions; `warn` if code risk is high without that agreement or medium, a public
function too short for the model has a high-severity detector hit,
the account is young, its code changed recently, it is a contract with no verifiable source, the deposit is large
and the agent never transacted with it before, or one of the receiver's recent NEAR Intents transactions scored
`high` (intents_activity; never a block on its own). A signal that could not be read is a reason to warn, never a
pass."""
from __future__ import annotations

THRESHOLDS = {
    "risk_high": 0.7,                       # code risk >= this -> label "high" -> block
    "risk_medium": 0.4,                     # code risk >= this -> label "medium" -> warn
    "min_account_age_days": 7,              # younger -> warn
    "recent_code_change_days": 7,           # code deployed within this many days -> warn
    "large_deposit_yocto": 100 * 10**24,    # 100 NEAR; first-time payment at or above -> warn
    # detectors-only fallback (no frozen model): per-function risk = noisy-or of these weights over its hits,
    # contract risk = max over functions. Detectors are uncalibrated signals, so alone they warn but never block.
    "detector_weight": {"high": 0.6, "medium": 0.3, "low": 0.1, "info": 0.0},
    "detectors_only_can_block": False,
    # NEAR Intents activity (near.service.intents): the receiver's recent transactions that touch intents.near,
    # scored by the frozen intents model. `high` warns; `medium` is listed as info: on the sealed test months'
    # collector-sampled normal Intents txs, 84/7,400 = 1.14% reached medium (0 high), 80 of them from one hour of
    # deposits failing while intents.near was paused; without the paused-contract txs, 4/7,301 = 0.055% (post hoc).
    # Medium is too noisy to act on (near/intents/reports/RESULTS.md).
    "intents_warn_label": "high",
    "intents_info_label": "medium",
    "intents_recent_txs": 20,               # score at most this many of the receiver's latest Intents txs
    "intents_index_rows": 40,               # latest account-index rows read to find them
    "intents_max_requests": 3,              # FastNEAR requests per check: 1 index page + up to 2 batches of 20 txs
    "intents_cache_s": 300,                 # per-receiver cache of a successful read
    "intents_reasons_max": 3,               # tx hashes named per reason
}
ORDER = {"allow": 0, "warn": 1, "block": 2}


def risk_label(risk: float) -> str:
    if risk >= THRESHOLDS["risk_high"]:
        return "high"
    return "medium" if risk >= THRESHOLDS["risk_medium"] else "low"


def _v(signals: dict, key: str):
    s = signals.get(key) or {}
    return s.get("value"), bool(s.get("available")), s.get("error")


def _near(yocto: int) -> str:
    return f"{yocto / 10**24:g} NEAR"


def _code_reason(cr: dict) -> str:
    top = ", ".join(f"{t.get('fn')} ({t.get('vuln_class_guess') or 'unknown'})" for t in (cr.get("top") or [])[:3])
    return (f"contract code risk is {cr['label']} ({cr['risk']:.2f}, {cr.get('version')})"
            + (f"; riskiest functions: {top}" if top else ""))


def _high_hits(fn: dict) -> bool:
    return any(h.get("severity") == "high" for h in fn.get("detector_hits") or [])


def _intents_tx(t: dict) -> str:
    rules = ", ".join(t.get("rules") or []) or "no rule; anomaly score above the high threshold"
    return f"{t.get('tx_hash')} ({rules})"


def _intents_reasons(s: dict) -> list[tuple[str, str]]:
    """intents_activity: `warn` when any recent Intents tx of the receiver is high, naming the tx and its rules;
    medium txs are listed with level `allow` (info, no verdict change). It never blocks: the label rests on
    per-transaction rules that also fire on the team's own regression tests, and on the receiver's role in a tx
    (signer, notified contract, counterparty) not being checked.

    Unreadable (FastNEAR down, rate-limited, timed out, answering data of an unexpected shape or leaving out requested
    transactions): `warn` for every receiver, with the error. FastNEAR's free quota (about 60 requests a minute per
    IP) is shared by every check, and the scoring endpoint is unauthenticated, so any client can drain it on purpose;
    if "unreadable" passed, draining the quota would turn the warn on an exploiter's account into an allow. Off
    mainnet the signal is "not applicable" (available, value None) and adds nothing."""
    v, ok, err = s.get("value"), bool(s.get("available")), s.get("error")
    t = THRESHOLDS
    if not ok:
        return [("warn", f"recent NEAR Intents activity of the receiver could not be read ({err})")]
    if not v:
        return []
    txs = v.get("txs") or []
    n, k = len(txs), t["intents_reasons_max"]
    out = []
    high = [x for x in txs if x.get("label") == t["intents_warn_label"]]
    med = [x for x in txs if x.get("label") == t["intents_info_label"]]
    if high:
        out.append(("warn", f"{len(high)} of the receiver's {n} most recent NEAR Intents transactions scored "
                            f"{t['intents_warn_label']}: " + "; ".join(_intents_tx(x) for x in high[:k])))
    if med:
        out.append(("allow", f"info: {len(med)} of the receiver's {n} most recent NEAR Intents transactions scored "
                             f"{t['intents_info_label']} (no verdict change): "
                             + "; ".join(_intents_tx(x) for x in med[:k])))
    return out


def decide(signals: dict, deposit_yocto=None, network: str = "mainnet", now_ns: int = 0) -> dict:
    """{verdict, score, reasons}. `score` is the code risk (0 for accounts without code), 1.0 when blocklisted."""
    out: list[tuple[str, str]] = []
    t = THRESHOLDS
    deposit = int(deposit_yocto or 0)

    exists, ok, err = _v(signals, "exists")
    is_contract, _, _ = _v(signals, "is_contract")
    if not ok:
        out.append(("warn", f"could not read the account over RPC ({err})"))
    elif not exists:
        out.append(("warn", "receiver account does not exist"))

    # shared blocklist: local store and on-chain oracle
    lb, ok, err = _v(signals, "local_blocklist")
    blocked = False
    if ok and lb:
        if lb.get("blocked"):
            blocked = True
            ev = ", ".join(c.get("evidence_url") or "?" for c in lb.get("confirmed") or [])
            out.append(("block", f"receiver is on the local blocklist (confirmed report: {ev})"))
        if lb.get("pending"):
            out.append(("warn", f"receiver has {lb['pending']} unconfirmed report(s) in the local blocklist"))
    elif not ok:
        out.append(("warn", f"local blocklist could not be read ({err})"))
    ob, ok, err = _v(signals, "onchain_blocked")
    if ok and ob:
        blocked = True
        out.append(("block", "the on-chain security oracle lists the receiver as blocked"))
    elif not ok and err != "not configured":
        out.append(("warn", f"on-chain blocklist could not be checked ({err})"))
    ov, ok, _ = _v(signals, "onchain_verdict")
    code_hash, _, _ = _v(signals, "code_hash")
    if ok and ov and int(ov.get("expires_at_ns") or 0) > now_ns:
        if ov.get("code_hash") and code_hash and ov["code_hash"] != code_hash:
            out.append(("warn", "contract code changed since the on-chain oracle's attestation"))
        elif ov.get("verdict") in ("block", "warn"):
            out.append((ov["verdict"], f"on-chain oracle attested '{ov['verdict']}' "
                                       f"(score {int(ov.get('score_bps') or 0) / 100:g}%)"))

    # code: source and risk
    cr, cr_ok, _ = _v(signals, "code_risk")
    src, _, src_err = _v(signals, "source")
    if is_contract:
        if cr_ok and cr and cr.get("label") == "high":
            if any(t.get("label") == "high" and _high_hits(t) for t in cr.get("top") or []):
                out.append(("block", _code_reason(cr)))
            else:
                out.append(("warn", _code_reason(cr) + "; no high-severity rule agrees on those functions, so the "
                                                       "model alone warns"))
        elif cr_ok and cr and cr.get("label") == "medium":
            out.append(("warn", _code_reason(cr)))
        elif cr_ok and cr and cr.get("n_functions") == 0:
            out.append(("warn", "contract source has no functions to score"))
        elif cr_ok and cr:
            flagged = [f.get("fn") for f in cr.get("functions") or []
                       if f.get("is_public") and not f.get("model_scored") and _high_hits(f)]
            if flagged:
                out.append(("warn", "high-severity rule hit on public functions the model does not score "
                                    f"(too short): {', '.join(sorted(set(flagged))[:5])}"))
        src = src or {}
        if src.get("origin") == "caller":
            out.append(("warn", "contract source was supplied by the caller and is not verified against "
                                "the deployed code"))
        elif src.get("origin") == "nep330" and not src.get("verified") and src.get("repo") and not src.get("error"):
            out.append(("warn", f"contract source link {src['repo']} is not pinned to a commit"))
        elif not (src.get("verified") and cr_ok and cr):
            why = src.get("error") or src_err or "no NEP-330 source metadata"
            out.append(("warn", f"receiver is a contract with no verifiable source ({why})"))

    # account history (meaningless on a fresh local sandbox chain)
    if network == "sandbox":
        out.append(("allow", "sandbox network: account age, code-change and interaction history checks skipped"))
    else:
        age, ok, err = _v(signals, "age_days")
        if not ok or age is None:
            out.append(("warn", f"account age is unknown ({err or 'no creation record'})"))
        elif age < t["min_account_age_days"]:
            out.append(("warn", f"account is {int(age)} days old (under {t['min_account_age_days']})"))
        if is_contract:
            cc, ok, err = _v(signals, "code_changed_days")
            if not ok:
                out.append(("warn", f"time of the last code change is unknown ({err})"))
            elif cc is not None and cc < t["recent_code_change_days"]:
                out.append(("warn", f"contract code was deployed {int(cc)} days ago "
                                    f"(under {t['recent_code_change_days']})"))
        if deposit >= t["large_deposit_yocto"]:
            prior, ok, err = _v(signals, "prior_interactions")
            if not ok:
                out.append(("warn", f"deposit is {_near(deposit)} and prior interactions are unknown ({err})"))
            elif not prior:
                out.append(("warn", f"no prior transactions from the agent to the receiver and the deposit is "
                                    f"{_near(deposit)} (threshold {_near(t['large_deposit_yocto'])})"))

    if "intents_activity" in signals:
        out += _intents_reasons(signals["intents_activity"] or {})

    verdict = max((lvl for lvl, _ in out), key=ORDER.get, default="allow")
    reasons = [r for lvl in ("block", "warn", "allow") for l2, r in out if l2 == lvl]
    if verdict == "allow" and not any(lvl != "allow" for lvl, _ in out):
        reasons.insert(0, "no risk signals: account checks passed" + (
            f" and code risk is low ({cr['risk']:.2f})" if is_contract and cr_ok and cr else ""))
    score = 1.0 if blocked else float(cr["risk"]) if (cr_ok and cr and is_contract) else 0.0
    return {"verdict": verdict, "score": round(score, 4), "reasons": reasons}
