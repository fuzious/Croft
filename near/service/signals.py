"""Account signals for a receiver: NEAR JSON-RPC (view_account, view calls) and the NearBlocks v3 API (age,
activity, code deployments, prior agent->receiver transactions). Every signal is {value, source, available, error};
a failed read is `available: False` with the error, never a default that looks safe."""
from __future__ import annotations

import base64
import json
import math
import os
import time
from datetime import date, datetime, timezone

import httpx

EMPTY_CODE_HASH = "11111111111111111111111111111111"
NETWORKS = {
    "mainnet": {"rpc": ["https://rpc.mainnet.fastnear.com", "https://rpc.mainnet.near.org"],
                "nearblocks": "https://api.nearblocks.io"},
    "testnet": {"rpc": ["https://rpc.testnet.fastnear.com", "https://rpc.testnet.near.org"],
                "nearblocks": "https://api-testnet.nearblocks.io"},
    "sandbox": {"rpc": ["http://127.0.0.1:3030"], "nearblocks": None},
}
NEARBLOCKS_TTL_S = 600
NEARBLOCKS_MAX_WAIT_S = 8.0   # total 429 backoff per request before the signal is marked unavailable
DAY_NS = 86_400 * 10**9
_nb_cache: dict = {}


class SignalError(Exception):
    pass


def load_config(env=None) -> dict:
    env = os.environ if env is None else env
    net = env.get("NEAR_NETWORK", "mainnet")
    if net not in NETWORKS:
        raise ValueError(f"NEAR_NETWORK must be one of {sorted(NETWORKS)}")
    d = NETWORKS[net]
    nb = env.get("NEARBLOCKS_API", d["nearblocks"]) if net != "sandbox" else env.get("NEARBLOCKS_API")
    return {"network": net, "rpc_urls": [env["NEAR_RPC_URL"]] if env.get("NEAR_RPC_URL") else d["rpc"],
            "oracle_contract_id": env.get("ORACLE_CONTRACT_ID") or None, "nearblocks_api": nb or None,
            "nearblocks_api_key": env.get("NEARBLOCKS_API_KEY") or None}


def sig(value, source: str, available: bool = True, error: str | None = None) -> dict:
    return {"value": value, "source": source, "available": available, "error": error}


# ---- NEAR JSON-RPC -------------------------------------------------------------------------------------------
def rpc(cfg: dict, method: str, params, timeout: float = 10.0) -> dict:
    """JSON-RPC result. Tries each RPC URL on transport errors; a handler error (e.g. UNKNOWN_ACCOUNT) raises
    SignalError with the error name and is not retried."""
    last = "no RPC URL"
    for url in cfg["rpc_urls"]:
        try:
            r = httpx.post(url, json={"jsonrpc": "2.0", "id": "oracle", "method": method, "params": params},
                           timeout=timeout)
            if r.status_code != 200:
                last = f"RPC HTTP {r.status_code}"
                continue
            body = r.json()
        except (httpx.HTTPError, ValueError) as e:
            last = f"RPC {type(e).__name__}"
            continue
        if not isinstance(body, dict):
            last = "malformed RPC response"
            continue
        if "error" in body:
            error = body["error"]
            if not isinstance(error, dict):
                raise SignalError("malformed RPC error")
            cause = error.get("cause")
            cause = (cause.get("name") if isinstance(cause, dict) else None) or error.get("name") or "RPC error"
            raise SignalError(cause)
        if not isinstance(body.get("result"), dict):
            last = "malformed RPC result"
            continue
        return body["result"]
    raise SignalError(last)


def view_account(cfg: dict, account_id: str) -> dict | None:
    """view_account result, or None when the account does not exist."""
    try:
        account = rpc(cfg, "query", {"request_type": "view_account", "finality": "final", "account_id": account_id})
        if not isinstance(account.get("code_hash"), str) or not account["code_hash"]:
            raise SignalError("account response has no code hash")
        return account
    except SignalError as e:
        if str(e) == "UNKNOWN_ACCOUNT":
            return None
        raise


def call_view(cfg: dict, account_id: str, method: str, args: dict) -> tuple[object, str | None]:
    """(decoded JSON return value, None) or (None, error string) for a contract view method."""
    params = {"request_type": "call_function", "finality": "final", "account_id": account_id, "method_name": method,
              "args_base64": base64.b64encode(json.dumps(args).encode()).decode()}
    try:
        res = rpc(cfg, "query", params)
    except SignalError as e:
        return None, str(e)
    if res.get("error"):
        return None, str(res["error"])
    try:
        return json.loads(bytes(res["result"]).decode() or "null"), None
    except (ValueError, KeyError, TypeError):
        return None, "undecodable view result"


# ---- NearBlocks v3 -------------------------------------------------------------------------------------------
def nearblocks(cfg: dict, path: str, params: dict | None = None) -> dict:
    """GET {NEARBLOCKS_API}{path}. Cached for NEARBLOCKS_TTL_S; on 429 waits (Retry-After or 1, 2, 4 s) up to
    NEARBLOCKS_MAX_WAIT_S in total, then raises SignalError."""
    base = cfg.get("nearblocks_api")
    if not base:
        raise SignalError(f"no NearBlocks indexer for {cfg['network']}")
    key = (base, path, tuple(sorted((params or {}).items())))
    hit = _nb_cache.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    headers = {"Authorization": f"Bearer {cfg['nearblocks_api_key']}"} if cfg.get("nearblocks_api_key") else {}
    waited, attempt = 0.0, 0
    while True:
        try:
            r = httpx.get(base.rstrip("/") + path, params=params, headers=headers, timeout=15.0)
        except httpx.HTTPError as e:
            raise SignalError(f"NearBlocks {type(e).__name__}") from None
        if r.status_code != 429:
            break
        try:
            wait = float(r.headers.get("retry-after") or 2**attempt)
        except ValueError:
            wait = 2.0**attempt
        if not math.isfinite(wait) or wait <= 0:
            wait = 2.0**attempt
        if waited + wait > NEARBLOCKS_MAX_WAIT_S:
            raise SignalError("NearBlocks rate limit (HTTP 429)")
        time.sleep(wait)
        waited, attempt = waited + wait, attempt + 1
    if r.status_code != 200:
        raise SignalError(f"NearBlocks HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError:
        raise SignalError("NearBlocks returned non-JSON") from None
    if not isinstance(data, dict) or "data" not in data:
        raise SignalError("malformed NearBlocks response")
    _nb_cache[key] = (time.time() + NEARBLOCKS_TTL_S, data)
    return data


def _days_since_ns(ts_ns, now_ns: int) -> float:
    return round((now_ns - int(ts_ns)) / DAY_NS, 2)


def _iso(ts_ns) -> str:
    return datetime.fromtimestamp(int(ts_ns) / 1e9, tz=timezone.utc).isoformat(timespec="seconds")


def history_signals(cfg: dict, account_id: str, is_contract: bool | None, agent_id: str | None, now_ns: int) -> dict:
    """age_days, tx_count, first/last_activity, code_changed_days, last_deploy_at, prior_interactions."""
    out, src = {}, "nearblocks"
    try:
        st = nearblocks(cfg, f"/v3/accounts/{account_id}/stats").get("data") or {}
        out["tx_count"] = sig(int(st["txns"]) if st.get("txns") is not None else None, f"{src}:/stats")
        out["first_activity"] = sig(st.get("first_day"), f"{src}:/stats")
        out["last_activity"] = sig(st.get("last_day"), f"{src}:/stats")
    except (SignalError, ValueError, TypeError, AttributeError) as e:
        for k in ("tx_count", "first_activity", "last_activity"):
            out[k] = sig(None, f"{src}:/stats", False, str(e))
    # age from the first active day: a lower bound on the true age, so the young-account check errs toward warning.
    # The creation record is fetched only when there is no activity, to spend one NearBlocks call instead of two.
    first = out["first_activity"]["value"]
    if first:
        try:
            today = datetime.fromtimestamp(now_ns / 1e9, tz=timezone.utc).date()
            out["age_days"] = sig(float((today - date.fromisoformat(first)).days), f"{src}:/stats first_day")
        except (ValueError, TypeError):
            out["age_days"] = sig(None, f"{src}:/stats first_day", False, "invalid first activity date")
    else:
        try:
            ts = (((nearblocks(cfg, f"/v3/accounts/{account_id}").get("data") or {}).get("created") or {})
                  .get("block_timestamp"))
            out["age_days"] = (sig(_days_since_ns(ts, now_ns), f"{src}:/accounts created") if ts else
                               sig(None, f"{src}:/accounts", False, "no creation record"))
        except (SignalError, ValueError, TypeError, AttributeError, OverflowError) as e:
            out["age_days"] = sig(None, f"{src}:/accounts", False, str(e))

    dsrc = f"{src}:/contract/deployments"
    if is_contract is False:
        out["code_changed_days"] = out["last_deploy_at"] = sig(None, "n/a: account has no contract code")
    elif is_contract is None:
        out["code_changed_days"] = out["last_deploy_at"] = sig(None, dsrc, False, "contract status unknown")
    else:
        try:
            deps = nearblocks(cfg, f"/v3/accounts/{account_id}/contract/deployments").get("data") or []
            ts = max((int((d.get("block") or {}).get("block_timestamp") or 0) for d in deps), default=0)
            if ts:
                out["last_deploy_at"] = sig(_iso(ts), dsrc)
                out["code_changed_days"] = sig(_days_since_ns(ts, now_ns), dsrc)
            else:
                out["code_changed_days"] = out["last_deploy_at"] = sig(None, dsrc, False, "no deployment record")
        except (SignalError, ValueError, TypeError, AttributeError, OverflowError) as e:
            out["code_changed_days"] = out["last_deploy_at"] = sig(None, dsrc, False, str(e))

    psrc = f"{src}:/accounts/{{agent}}/txns?receiver="
    if not agent_id:
        out["prior_interactions"] = sig(None, psrc, False, "no agent_id given")
    else:
        try:
            txs = nearblocks(cfg, f"/v3/accounts/{agent_id}/txns", {"receiver": account_id, "limit": 1})
            if not isinstance(txs.get("data"), list) or any(not isinstance(tx, dict) for tx in txs["data"]):
                raise SignalError("invalid transaction history")
            out["prior_interactions"] = sig(bool(txs.get("data")), psrc)
        except SignalError as e:
            out["prior_interactions"] = sig(None, psrc, False, str(e))
    return out


# ---- everything for one receiver ------------------------------------------------------------------------------
def onchain_oracle_signals(cfg: dict, account_id: str) -> dict:
    oid = cfg.get("oracle_contract_id")
    if not oid:
        return {k: sig(None, "oracle contract", False, "not configured") for k in ("onchain_blocked", "onchain_verdict")}
    out = {}
    for key, method in (("onchain_blocked", "is_blocked"), ("onchain_verdict", "get_verdict")):
        v, err = call_view(cfg, oid, method, {"account_id": account_id})
        if err is None:
            if key == "onchain_blocked" and type(v) is not bool:
                err = "invalid blocklist response"
            elif key == "onchain_verdict" and v is not None:
                try:
                    valid = (isinstance(v, dict) and v.get("verdict") in ("allow", "warn", "block")
                             and isinstance(v.get("code_hash"), str)
                             and type(v.get("score_bps")) is int and 0 <= v["score_bps"] <= 10000
                             and isinstance(v.get("expires_at_ns"), (str, int))
                             and str(v["expires_at_ns"]).isdigit() and 0 <= int(v["expires_at_ns"]) < 2**64)
                except (TypeError, ValueError):
                    valid = False
                if not valid:
                    err = "invalid verdict response"
        if err:
            v = None
        out[key] = sig(v, f"rpc:{oid}.{method}", err is None, err)
    return out


def account_signals(cfg: dict, account_id: str, agent_id: str | None = None, now_ns: int | None = None) -> dict:
    now_ns = now_ns or time.time_ns()
    src = "rpc:view_account"
    try:
        acc = view_account(cfg, account_id)
        if acc is None:
            out = {"exists": sig(False, src), "is_contract": sig(False, src)}
            for k in ("balance_yocto", "code_hash", "storage_usage"):
                out[k] = sig(None, src)
        else:
            out = {"exists": sig(True, src), "balance_yocto": sig(acc.get("amount"), src),
                   "code_hash": sig(acc.get("code_hash"), src), "storage_usage": sig(acc.get("storage_usage"), src),
                   "is_contract": sig(acc.get("code_hash") not in (None, EMPTY_CODE_HASH), src)}
    except SignalError as e:
        out = {k: sig(None, src, False, str(e))
               for k in ("exists", "is_contract", "balance_yocto", "code_hash", "storage_usage")}
    is_contract = out["is_contract"]["value"] if out["is_contract"]["available"] else None
    out.update(history_signals(cfg, account_id, is_contract, agent_id, now_ns))
    out.update(onchain_oracle_signals(cfg, account_id))
    return out
