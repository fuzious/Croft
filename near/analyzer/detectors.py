"""NEAR-specific vulnerability detectors over one extracted function (regex over comment- and string-stripped code).
Patterns follow BlockSec Rustle's detectors and NEAR docs' security pages. They are model features, not verdicts,
so each one is tuned for precision: it fires only when the code shows the pattern and none of its usual guards."""
from __future__ import annotations

import re
from functools import lru_cache

SEVERITY = {"high": 3, "medium": 2, "low": 1, "info": 0}

_STRIP = re.compile(r'//[^\n]*|/\*.*?\*/|r(#*)".*?"\1|b?"(?:\\.|[^"\\])*"|b?\'(?:\\.|[^\\\'\n])\'', re.S)


def _blank(m: re.Match) -> str:
    t = m.group(0)
    if t.startswith(("//", "/*")):
        return re.sub(r"[^\n]", " ", t)
    return t[0] + re.sub(r"[^\n]", " ", t[1:-1]) + t[-1] if len(t) >= 2 else t


def strip_code(code: str) -> str:
    """Blank comments and string/char literal contents, keeping length and newlines (line numbers stay valid)."""
    return _STRIP.sub(_blank, code)


def strip_comments(code: str) -> str:
    return _STRIP.sub(lambda m: _blank(m) if m.group(0).startswith(("//", "/*")) else m.group(0), code)


# --- shared patterns -------------------------------------------------------------------------------------------
PREDECESSOR = re.compile(r"\bpredecessor_account_id\s*\(")
SELF_CHECK = re.compile(
    r"predecessor_account_id\(\)\s*(?:==|!=)\s*(?:env::)?current_account_id\(\)"
    r"|current_account_id\(\)\s*(?:==|!=)\s*(?:env::)?predecessor_account_id\(\)"
    r"|assert_(?:eq|ne)!\(\s*(?:env::)?(?:predecessor|current)_account_id\(\)\s*,\s*(?:env::)?(?:predecessor|current)_account_id\(\)"
    r"|\b(?:assert|require|only|check)_(?:self|private|is_self|contract_itself)\s*\(")
AUTH_HELPER = re.compile(
    r"\b(?:assert|require|check|only|ensure|verify|validate|is|abort_if_not|panic_if_not)_?(?:\w*_)?"
    r"(?:owner|owners|admin|admins|operator|operators|guardian|guardians|manager|governance|gov|dao|council|role|roles"
    r"|authorized|authorised|auth|member|members|whitelisted|allowed|privileged|controller|minter|relayer|keeper|executor|self)\w*\s*\("
    r"|\bacl_\w+\s*\(|\bhas_role\s*\(|\bowner_only\s*\(")
AUTH_COMPARE = re.compile(
    r"\bself\.(?:\w+\.)*\w*(?:owner|admin|operator|guardian|governance|dao|council)\w*(?:\(\))?\s*(?:==|!=)"
    r"|(?:==|!=)\s*&?\s*self\.(?:\w+\.)*\w*(?:owner|admin|operator|guardian|governance|dao|council)\w*")
AUTH_ATTR = re.compile(r"#\[\s*(?:only|access_control_any|access_control|owner_only|only_owner|only_role)\b")
YOCTO = re.compile(r"\bassert_(?:at_least_)?one_yocto\b|\b\w*one_yocto\w*\s*\(|\bONE_YOCTO\b|\bassert_1yocto\b"
                   r"|attached_deposit\(\)(?:\.as_yoctonear\(\))?\s*(?:==|>=)\s*(?:1|NearToken::from_yoctonear\(1\))\b")
PROMISE_RESULT = re.compile(r"promise_result|is_promise_success|promise_success|promise_results_count|PromiseResult"
                            r"|PromiseError|is_promise_\w+|promise_ok")
CALLBACK_ATTRS = {"callback_result", "callback_unwrap", "callback", "callback_vec"}
RECEIVERS = {"ft_on_transfer", "nft_on_transfer", "mt_on_transfer", "nft_on_approve"}
CALLBACK_NAME = re.compile(r"callback|resolve|^on_|^after_|_cb$|^handle_\w*result")
WRITE_ASSIGN = re.compile(r"\bself\.[\w.\[\]]+\s*(?:[+\-*/%|&^]|<<|>>)?=(?!=)")
COLL_INSERT = re.compile(r"\.\s*(?:insert|push|extend|append|or_insert\w*|or_default|set|replace)\s*\(")
COLL_REMOVE = re.compile(r"\.\s*(?:remove|pop|clear|retain|swap_remove|truncate|drain|take)\s*\(")
SELF_MUTATE = re.compile(
    r"\bself\.(?:\w+\.)*(?:internal_\w+|\w*(?:withdraw|deposit|transfer|sub|add|increase|decrease|update|set|save"
    r"|burn|mint|lock|unlock|register|remove|insert|record|apply|settle|credit|debit)\w*)\s*\(")
VALUE_CALL = re.compile(r"(?:\.|::)\s*(ft_transfer|ft_transfer_call|nft_transfer|nft_transfer_call|mt_transfer"
                        r"|mt_batch_transfer|mt_transfer_call|mt_batch_transfer_call|withdraw|unstake|deposit_and_stake)\s*\(")
EXT_CALL = re.compile(r"\bext_\w+\s*::|::\s*ext\s*\(|Promise::new\s*\(|\.function_call\w*\s*\(|promise_create|promise_then")
THEN = re.compile(r"\.\s*then\s*\(")
ASSIGN_OR_CHECK = re.compile(r"(?:assert\w*!|require!)\s*\([^;]*?(?:\bself\.|\.get\s*\()|\bif\s+[^{;]*\bself\.[^{;]*[<>]")
STORAGE_WORDS = re.compile(r"storage|attached_deposit|deposit|STORAGE|register|refund", re.I)
DEPLOY = re.compile(r"deploy_contract\s*\(|promise_batch_action_deploy_contract|DeployContract")
NARROW_AS = re.compile(r"\bas\s+(?:u64|u32|u16|u8|i64|i32|i16|i8|usize|isize)\b")
AMOUNT = re.compile(r"amount|balance|supply|shares?\b|deposit|value|price|reward|stake|total|fee|liquidity|debt"
                    r"|collateral|\.0\b|yocto", re.I)
WRAPPING = re.compile(r"\.\s*(?:wrapping|overflowing|unchecked)_(?:add|sub|mul|pow|neg|div)\s*\(")
FLOAT_AS = re.compile(r"\bas\s+f(?:32|64)\b")
ROUND = re.compile(r"\.\s*round\s*\(\s*\)")
CHECKED_DIV_MUL = re.compile(r"checked_div\s*\([^;]*?checked_mul\s*\(")
LOOP_SELF = re.compile(
    r"\bfor\s+[^{;]*?\bin\s+(?:&\s*(?:mut\s+)?)?self\.[\w.]+?(?:\.(?:iter|iter_mut|keys|values|values_mut|to_vec|into_iter)\s*\(\s*\))?"
    r"(?P<tail>[^{]*)\{"
    r"|\bfor\s+\w+\s+in\s+0\s*\.\.=?\s*self\.[\w.]+\.len\s*\(\s*\)(?P<tail2>[^{]*)\{"
    r"|\bself\.[\w.]+\.(?:iter|iter_mut|values|keys)\s*\(\s*\)(?P<tail3>[^;]*?)\.\s*(?:for_each|fold|sum|collect|map)\s*\(")
PAGINATION = re.compile(r"\.\s*(?:take|skip|step_by)\s*\(|from_index|limit", re.I)
RAND_SOURCE = r"(?:block_timestamp\w*|random_seed\w*|block_height|block_index|epoch_height)\s*\(\s*\)"
RANDOMNESS = re.compile(rf"{RAND_SOURCE}[^;{{}}]{{0,80}}%|%[^;{{}}]{{0,80}}{RAND_SOURCE}|random_seed\w*\s*\(\s*\)\s*\[")
FRESHNESS = re.compile(r"timestamp|recency|max_age|stale|expir|valid_until|updated|last_update|\bage\b|duration"
                       r"|block_height|epoch|fresh", re.I)
ORACLE_SIG = re.compile(r"PriceData|oracle|price_data|asset_prices|PriceFeed|ExchangeRate", re.I)
PRIV_NAME = re.compile(
    r"^(?:set_owner|change_owner|transfer_owner\w*|set_admin\w*|add_admin\w*|remove_admin\w*"
    r"|(?:add|remove|set|grant|revoke)_(?:guardian|operator|manager|minter|relayer|validator|oracle|keeper|admin|owner"
    r"|role|executor|council|whitelist|blacklist)\w*"
    r"|pause\w*|unpause\w*|set_paused|resume_contract|set_\w*fee\w*|update_fee\w*|change_fee\w*"
    r"|set_config\w*|update_config\w*|change_config\w*|set_price\w*|set_oracle\w*|set_rate\w*|set_treasury\w*"
    r"|mint|mint_\w+|\w+_mint|withdraw_(?:all|fees?|protocol\w*|owner\w*|treasury|reserves?|admin\w*)"
    r"|claim_(?:protocol_)?fees|emergency\w*|rescue\w*|sweep\w*|upgrade\w*|set_code|update_contract"
    r"|set_\w+_contract(?:_id)?|whitelist_\w+|blacklist_\w+|ban_\w+)$")
NFT_OWNER_METHODS = {"nft_approve", "nft_revoke", "nft_revoke_all"}
YOCTO_METHODS = {"ft_transfer", "ft_transfer_call", "nft_transfer", "nft_transfer_call", "storage_withdraw",
                 "storage_unregister", "mt_transfer", "mt_batch_transfer", "mt_transfer_call",
                 "mt_batch_transfer_call", "nft_approve", "nft_revoke", "nft_revoke_all"}
BUILDERS = {"ext", "with_static_gas", "with_attached_deposit", "with_unused_gas_weight", "new", "then", "and",
            "clone", "into", "current_account_id", "as_ref", "to_owned"}
SELF_EXT = re.compile(r"\b(?:ext_self\w*|ext_contract_self|self_ext|ext_this)\s*::\s*(\w+)\s*\(|\bSelf\s*::\s*(ext)\s*\("
                      r"|\bext_self\w*\s*\(\s*\)\s*\.\s*(\w+)\s*\(")
EXT_TRAIT = re.compile(r"#\[\s*(?:near_sdk::)?ext_contract\s*\(\s*(\w+)\s*\)\s*\]\s*(?:pub(?:\([^)]*\))?\s+)?trait\s+(\w+)[^{]*\{")


def _balanced(s: str, i: int) -> int:
    """Index just past the bracket group opening at s[i] ('(' / '{' / '[')."""
    depth = 0
    for j in range(i, len(s)):
        c = s[j]
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
            if depth == 0:
                return j + 1
    return len(s)


@lru_cache(maxsize=256)
def callback_names(file_src: str) -> frozenset:
    """Methods this file schedules as callbacks on itself: Self::ext(..).cb(), ext_self::cb(), ext_contract self traits,
    function_call("cb") inside a .then(..) that targets current_account_id."""
    s = strip_comments(file_src)
    out = set()
    for m in SELF_EXT.finditer(s):
        name = m.group(1) or m.group(2) or m.group(3)
        if name != "ext":
            if name not in BUILDERS:
                out.add(name)
            continue
        j = _balanced(s, s.index("(", m.start(1) if m.group(1) else m.start(2)))
        while True:
            mm = re.compile(r"\s*\.\s*(\w+)\s*\(").match(s, j)
            if not mm:
                break
            if mm.group(1) not in BUILDERS:
                out.add(mm.group(1))
                break
            j = _balanced(s, mm.end() - 1)
    for m in THEN.finditer(s):
        seg = s[m.end() - 1:_balanced(s, m.end() - 1)]
        if "current_account_id" in seg:
            out.update(re.findall(r'function_call\w*\s*\(\s*b?"(\w+)"', seg))
    for m in EXT_TRAIT.finditer(s):
        if re.search(r"self|callback|resolver", m.group(1) + m.group(2), re.I):
            body = s[m.end() - 1:_balanced(s, m.end() - 1)]
            out.update(re.findall(r"\bfn\s+(\w+)", body))
    return frozenset(out)


@lru_cache(maxsize=256)
def _file_fn_bodies(file_src: str) -> dict:
    """fn name -> stripped text up to the next fn (cheap helper lookup)."""
    s = strip_code(file_src)
    starts = [(m.start(), m.group(1)) for m in re.finditer(r"\bfn\s+(\w+)", s)]
    out = {}
    for k, (i, name) in enumerate(starts):
        out.setdefault(name, s[i:starts[k + 1][0] if k + 1 < len(starts) else len(s)])
    return out


def _compared(text: str, api: str) -> re.Match | None:
    """First place where env::<api>() (or a local bound to it) is compared / asserted / looked up in a set."""
    names = [rf"(?:env::)?{api}\(\)"] + [
        re.escape(v) + r"\b" for v in re.findall(
            rf"let\s+(?:mut\s+)?(\w+)\s*(?::\s*[\w:]+\s*)?=\s*(?:env::)?{api}\(\)", text)]
    alt = "|".join(names)
    return re.search(
        rf"(?:{alt})\s*(?:\.clone\(\)\s*)?(?:==|!=)|(?:==|!=)\s*&?\s*(?:{alt})|assert_(?:eq|ne)!\(\s*&?\s*(?:{alt})"
        rf"|assert_(?:eq|ne)!\([^;]*?,\s*&?\s*(?:{alt})|contains(?:_key)?\s*\(\s*&?\s*(?:{alt})"
        rf"|\b(?:is|assert|check|only)_\w*\(\s*&?\s*(?:{alt})", text)


def context(fn: dict, file_src: str | None = None) -> dict:
    """Everything the detectors and features share, computed once per function."""
    code = fn.get("code") or ""
    s = strip_code(code)
    name = fn.get("fn") or ""
    m = re.search(rf"\bfn\s+{re.escape(name)}\b", s) if name else None
    sig_start = m.start() if m else 0
    b = s.find("{", m.end() if m else 0)
    b = len(s) if b < 0 else b
    sig, body, head = s[sig_start:b], s[b:], s[:sig_start]
    attrs = set(fn.get("attrs") or [])
    mut = bool(re.search(r"&\s*(?:'\w+\s+)?mut\s+self\b", sig))
    view = not mut and bool(re.search(r"&\s*(?:'\w+\s+)?self\b", sig))
    has_self = mut or view or bool(re.search(r"\(\s*(?:mut\s+)?self\b", sig))
    is_public = bool(fn.get("is_public"))
    entry = "no_mangle" in attrs or (is_public and (bool(fn.get("is_near_bindgen"))
                                                     or (fn.get("impl") is None and has_self)))
    private = "private" in attrs or bool(SELF_CHECK.search(body))
    cbs = callback_names(file_src) if file_src else frozenset()
    pred_cmp = _compared(body, "predecessor_account_id")
    ctx = {
        "fn": fn, "name": name, "s": s, "sig": sig, "body": body, "head": head, "body_off": b, "attrs": attrs,
        "start_line": int(fn.get("start_line") or 1), "file_src": file_src,
        "mut": mut, "view": view, "has_self": has_self, "entry": entry, "private": private,
        "init": "init" in attrs, "payable": "payable" in attrs or bool(fn.get("is_payable")),
        "uses_pred": bool(PREDECESSOR.search(body)), "pred_cmp": pred_cmp,
        "promise_api": bool(PROMISE_RESULT.search(body)) or bool(attrs & CALLBACK_ATTRS),
        "in_cb_set": name in cbs,
    }
    ctx["auth"] = (private or bool(AUTH_HELPER.search(body)) or bool(AUTH_COMPARE.search(body))
                   or bool(AUTH_ATTR.search(head)) or pred_cmp is not None)
    ctx["callback"] = name not in RECEIVERS and (ctx["in_cb_set"] or ctx["promise_api"] or "callback" in name.lower())
    ctx["writes"] = bool(WRITE_ASSIGN.search(body) or COLL_INSERT.search(body) or COLL_REMOVE.search(body)
                         or SELF_MUTATE.search(body))
    ctx["ext_value"] = _ext_value_call(body)
    return ctx


def _ext_value_call(body: str) -> re.Match | None:
    """A value-moving call (ft_transfer, nft_transfer, withdraw, ...) made on an external-call builder."""
    for m in VALUE_CALL.finditer(body):
        stmt_start = max(body.rfind(";", 0, m.start()), body.rfind("{", 0, m.start()), body.rfind("}", 0, m.start()))
        if EXT_CALL.search(body, stmt_start + 1, m.start(1)) or re.search(
                r"\bext_\w+\s*::\s*$", body[max(0, m.start() - 60):m.start() + 1]):
            return m
    return None


def _line(ctx: dict, idx_in_body: int | None = None) -> int:
    i = ctx["body_off"] + idx_in_body if idx_in_body is not None else len(ctx["head"])
    return ctx["start_line"] + ctx["s"].count("\n", 0, i)


def _hit(ctx, detector, cls, sev, msg, idx=None):
    return {"detector": detector, "vuln_class": cls, "line": _line(ctx, idx), "message": msg, "severity": sev}


# --- detectors: each takes ctx, returns a list of hits ---------------------------------------------------------
def non_private_callback(c):
    acts = c["writes"] or "transfer" in c["body"] or EXT_CALL.search(c["body"])
    if c["entry"] and c["mut"] and c["callback"] and not c["private"] and not c["init"] and acts:
        return [_hit(c, "non_private_callback", "non_private_callback", "high",
                     f"callback `{c['name']}` is callable by anyone: no #[private] or predecessor == current_account_id")]
    return []


def unhandled_promise_result(c):
    out = []
    body = c["body"]
    is_cb = c["in_cb_set"] or bool(CALLBACK_NAME.search(c["name"]))
    if is_cb and c["entry"] and c["name"] not in RECEIVERS and (c["private"] or c["in_cb_set"]) \
            and not c["promise_api"] and not _delegates_result(c) and (c["writes"] or "transfer" in body):
        out.append(_hit(c, "callback_ignores_result", "unhandled_promise_result", "medium",
                        f"callback `{c['name']}` changes state without checking the promise result"))
    m = c["ext_value"]
    returns = re.search(r"->\s*[^{]*Promise", c["sig"]) or re.search(r"\bpromise_return\b|\breturn\b", body)
    if m and not THEN.search(body) and ((c["entry"] and c["mut"] and c["writes"]) or not returns):
        out.append(_hit(c, "unhandled_value_promise", "unhandled_promise_result", "medium",
                        f"`{m.group(1)}` promise has no callback: state changed here is not rolled back if it fails",
                        m.start()))
    return out


def _delegates_result(c) -> bool:
    """The callback hands the promise result to a helper (self.token.internal_ft_resolve_transfer, ...)."""
    calls = re.findall(r"\.\s*(\w+)\s*\(", c["body"])
    if any("resolve" in h or "promise" in h or "callback" in h for h in calls):
        return True
    bodies = _file_fn_bodies(c["file_src"]) if c["file_src"] else {}
    return any(PROMISE_RESULT.search(bodies.get(h, "")) for h in calls if h != c["name"])


def _success_arm(body: str) -> str:
    m = (re.search(r"PromiseResult::Successful\s*\([^)]*\)\s*=>\s*", body)
         or re.search(r"\bOk\s*\([^)]*\)\s*=>\s*", body))
    if m:
        j = m.end()
        if j < len(body) and body[j] == "{":
            return body[j:_balanced(body, j)]
        end = re.compile(r",\s*\n|\n\s*\w[\w:]*(?:\([^)]*\))?\s*=>").search(body, j)
        return body[j:end.start() if end else len(body)]
    m = re.search(r"\bif\s+(?:env::)?is_promise_success\s*\(\s*\)\s*\{|\bif\s+\w+\.is_ok\s*\(\s*\)\s*\{"
                  r"|\bif\s+let\s+Ok\s*\([^)]*\)\s*=[^{]*\{", body)
    return body[m.end() - 1:_balanced(body, m.end() - 1)] if m else ""


DECREMENT = re.compile(r"-=|checked_sub|saturating_sub|internal_withdraw|\b(?:\w+_)?(?:burn|debit|decrease)\w*\s*\(")


def async_reentrancy(c):
    body, out = c["body"], []
    if c["entry"] and c["mut"] and c["ext_value"] and THEN.search(body) and not c["writes"]:
        chk = ASSIGN_OR_CHECK.search(body)
        if chk:
            out.append(_hit(c, "check_without_update", "async_reentrancy", "medium",
                            "balance checked but not updated before the cross-contract call; the update is deferred "
                            "to the callback, so the method can be re-entered before it runs", chk.start()))
    if c["callback"] and c["promise_api"]:
        arm = _success_arm(body)
        d = DECREMENT.search(arm)
        if d:
            out.append(_hit(c, "deduct_after_success", "async_reentrancy", "high",
                            "balance is deducted only after the cross-contract call succeeds (in the callback); "
                            "deduct before the call and roll back on failure", body.find(arm) + d.start()))
    return out


def missing_access_control(c):
    name = c["name"]
    if name in NFT_OWNER_METHODS and c["mut"] and c["pred_cmp"] is None and not c["private"] \
            and not AUTH_HELPER.search(c["body"]) and not re.search(rf"\bself\b[\w.()\s]*?\.\s*(?:internal_)?{name}\w*\s*\(", c["body"]):
        return [_hit(c, "nft_approval_without_owner", "missing_access_control", "high",
                     f"`{name}` does not check that the caller owns the token")]
    if not (c["entry"] and c["mut"]) or c["init"] or c["auth"] or c["uses_pred"]:
        return []
    if PRIV_NAME.match(name) and not ("mint" in name and "attached_deposit" in c["body"]):
        return [_hit(c, "privileged_without_auth", "missing_access_control", "high",
                     f"privileged method `{name}` has no owner/role/predecessor check")]
    return []


def missing_one_yocto(c):
    body, name = c["body"], c["name"]
    if not (c["entry"] and c["mut"]) or c["init"] or YOCTO.search(body) or "private" in c["attrs"] or c["callback"] \
            or name in RECEIVERS or re.search(r"_on_(?:transfer|call|approve)$", name) \
            or (c["payable"] and "attached_deposit" in body):  # a real deposit already needs a full-access key
        return []
    if name in YOCTO_METHODS:
        if re.search(rf"\bself\b[\w.()\s]*?\.\s*(?:internal_)?{name}\w*\s*\(", body) or not (
                c["writes"] or c["ext_value"] or "transfer" in body):
            return []  # delegates to the standard implementation (which asserts the deposit), or does nothing
        return [_hit(c, "nep_method_without_yocto", "missing_one_yocto", "medium",
                     f"`{name}` must require exactly one yoctoNEAR (assert_one_yocto) per the NEP standard")]
    if (bool(AUTH_HELPER.search(body)) or bool(AUTH_COMPARE.search(body)) or c["pred_cmp"] is not None) \
            and not SELF_CHECK.search(body):
        return [_hit(c, "privileged_without_yocto", "missing_one_yocto", "medium",
                     f"privileged method `{name}` lacks assert_one_yocto: callable with a function-call access key")]
    return []


def signer_auth(c):
    body = c["body"]
    m = _compared(body, "signer_account_id")
    if m:
        return [_hit(c, "signer_comparison", "signer_auth", "high",
                     "authorization uses env::signer_account_id(); use predecessor_account_id()", m.start())]
    m = re.search(r"\.get\s*\(\s*&?\s*(?:env::)?signer_account_id\(\)|Promise::new\s*\(\s*(?:env::)?signer_account_id\(\)",
                  body)
    if m and (c["ext_value"] or "transfer" in body or c["writes"]):
        return [_hit(c, "signer_identity", "signer_auth", "medium",
                     "funds are keyed or sent by signer_account_id(); a contract in the call chain can act for the "
                     "signer", m.start())]
    return []


def unguarded_upgrade(c):
    body, head = c["body"], c["head"]
    strict_auth = (c["private"] or bool(AUTH_HELPER.search(body)) or bool(AUTH_COMPARE.search(body))
                   or bool(AUTH_ATTR.search(head)) or c["pred_cmp"] is not None)
    if strict_auth:
        return []
    d = DEPLOY.search(body)
    if d and "create_account" not in body and (c["entry"] or "no_mangle" in c["attrs"]):
        return [_hit(c, "deploy_without_auth", "unguarded_upgrade", "high",
                     "contract code is deployed without an owner check", d.start())]
    if c["init"] and re.search(r"#\[\s*init\s*\(\s*ignore_state", head) and c["fn"].get("is_public"):
        return [_hit(c, "reinit_without_auth", "unguarded_upgrade", "high",
                     "#[init(ignore_state)] method without #[private]: anyone can overwrite contract state")]
    return []


def _operand_before(s: str, i: int) -> str:
    j = i - 1
    while j >= 0 and s[j].isspace():
        j -= 1
    if j >= 0 and s[j] == ")":
        depth = 0
        for k in range(j, -1, -1):
            depth += s[k] == ")"
            depth -= s[k] == "("
            if depth == 0:
                pre = re.search(r"[\w.:]*$", s[max(0, k - 40):k])
                return (pre.group(0) if pre else "") + s[k:j + 1]
        return s[:j + 1]
    m = re.search(r"(?:[\w.:]|\(\))*$", s[max(0, j - 60):j + 1])
    return m.group(0) if m else ""


def _statement(s: str, i: int) -> str:
    a = max(s.rfind(";", 0, i), s.rfind("{", 0, i), s.rfind("}", 0, i)) + 1
    b = s.find(";", i)
    return s[a:b if b >= 0 else len(s)]


def unsafe_arithmetic(c):
    body = c["body"]
    for m in NARROW_AS.finditer(body):
        op = _operand_before(body, m.start())
        if AMOUNT.search(op):
            return [_hit(c, "narrowing_cast", "unsafe_arithmetic", "medium",
                         f"amount `{op.strip()[:40]}` cast with `{m.group(0)}` can silently truncate", m.start())]
    for m in WRAPPING.finditer(body):
        if AMOUNT.search(_statement(body, m.start())):
            return [_hit(c, "wrapping_math", "unsafe_arithmetic", "medium",
                         "wrapping/unchecked arithmetic on an amount overflows silently", m.start())]
    return []


_TOK = re.compile(r"\w+|::|->|=>|==|!=|<=|>=|&&|\|\||<<=|>>=|[+\-*/%&|^]=|\S")
_STOP = {";", ",", "{", "}", "=", "==", "!=", "<", ">", "<=", ">=", "&&", "||", "=>", "+", "-", "+=", "-=",
         "*=", "/=", "%=", "?", "..", "return", "let"}


def _div_before_mul(body: str) -> int | None:
    toks = [(m.group(0), m.start()) for m in _TOK.finditer(body)]
    n = len(toks)
    for i, (t, pos) in enumerate(toks):
        if t != "/" or i == 0:
            continue
        depth, j = 0, i + 1
        while j < n:
            u = toks[j][0]
            if u in "([":
                depth += 1
            elif u in ")]":
                depth = max(0, depth - 1)
            elif depth == 0 and u in _STOP:
                break
            elif depth == 0 and u == "*" and (toks[j - 1][0][-1].isalnum() or toks[j - 1][0] in (")", "]", "_")):
                divisor = "".join(x for x, _ in toks[i + 1:j] if x not in ("as",) and not re.fullmatch(r"[iu]\d+|usize|f\d\d", x))
                k = j + 1
                mult = []
                while k < n and (re.fullmatch(r"\w+", toks[k][0]) or toks[k][0] in (".", "::")):
                    mult.append(toks[k][0])
                    k += 1
                mult = "".join(x for x in mult if not re.fullmatch(r"[iu]\d+|usize|f\d\d|as", x))
                if divisor.strip("()") != mult:
                    return pos
                break
            j += 1
    return None


def precision_rounding(c):
    body = c["body"]
    p = _div_before_mul(body)
    if p is not None:
        return [_hit(c, "div_before_mul", "precision_rounding", "medium",
                     "division before multiplication loses precision; multiply first", p)]
    for m in re.finditer(r"\blet\s+(?:mut\s+)?(\w+)\s*(?::[^=;]+)?=([^;]*?[\w)\]]\s*/\s*[^;]*);", body):
        if "*" in m.group(2).split("/", 1)[1]:
            continue  # handled (or excused) by the single-expression check
        divisor = re.sub(r"\s+", "", m.group(2).rsplit("/", 1)[1])
        rest = body[m.end():]
        use = re.search(rf"(?<![\w.])\b{m.group(1)}\b\s*\*(?!=)|[\w)\]]\s*\*\s*\b{m.group(1)}\b", rest)
        other = (re.sub(r"\s+", "", rest[use.end():use.end() + len(divisor) + 20]) if use and rest[use.end() - 1] == "*"
                 else re.sub(r"\s+", "", rest[max(0, use.start() - len(divisor) - 20):use.start() + 1]) if use else "")
        if use and divisor not in other:  # q = x / d; x - q * d is the remainder idiom, not precision loss
            return [_hit(c, "div_before_mul", "precision_rounding", "medium",
                         f"`{m.group(1)}` is a quotient that is multiplied later; multiply first", m.end() + use.start())]
    m = CHECKED_DIV_MUL.search(body)
    if m:
        return [_hit(c, "div_before_mul", "precision_rounding", "medium",
                     "checked_div before checked_mul loses precision", m.start())]
    m = ROUND.search(body)
    if m:
        return [_hit(c, "round_direction", "precision_rounding", "low",
                     "round() has no direction; use floor/ceil in the protocol's favour", m.start())]
    for m in FLOAT_AS.finditer(body):
        if AMOUNT.search(_operand_before(body, m.start())):
            return [_hit(c, "float_amount", "precision_rounding", "low",
                         "amount converted to floating point", m.start())]
    return []


def storage_staking(c):
    body, name = c["body"], c["name"]
    used = re.sub(r"let\s+(?:mut\s+)?force\s*(?::[^=;]+)?=\s*force\b", "", body)
    if name == "storage_unregister" and re.search(r"\bforce\b", c["sig"]) and not re.search(r"\bforce\b", used) \
            and COLL_REMOVE.search(body):
        return [_hit(c, "unregister_ignores_balance", "storage_staking", "medium",
                     "storage_unregister removes the account without checking its balance or the force flag")]
    if not (c["entry"] and c["mut"]) or c["auth"] or c["callback"] or c["init"] or STORAGE_WORDS.search(body):
        return []
    for m in re.finditer(r"\bself\.([\w.]+?)\.\s*(insert|push)\s*\(", body):
        coll = re.escape(m.group(1))
        if m.group(2) == "push" or not re.search(rf"\bself\.{coll}\.\s*(?:get|get_mut|contains_key|entry)\s*\(", body):
            return [_hit(c, "state_growth_unpaid", "storage_staking", "medium",
                         f"`self.{m.group(1)}` grows on a public call with no storage deposit check", m.start())]
    return []


def ft_receiver_trust(c):
    body, name = c["body"], c["name"]
    if name not in RECEIVERS or not c["entry"] or c["uses_pred"]:
        return []
    if c["file_src"]:  # the check may live in a helper this method calls
        bodies = _file_fn_bodies(c["file_src"])
        for h in re.findall(r"\bself\.(\w+)\s*\(", body):
            if h != name and PREDECESSOR.search(bodies.get(h, "")):
                return []
    if c["writes"] or re.search(r"\bmsg\b", body):
        return [_hit(c, "receiver_trusts_caller", "ft_receiver_trust", "high",
                     f"`{name}` never checks predecessor_account_id (the token contract): any contract can call it "
                     "and fake a deposit")]
    return []


DEFAULT_ZERO = re.compile(r"\bself\.([\w.]+?)\.get\s*\([^;]*?\)\s*\.\s*(?:unwrap_or\s*\(\s*(?:0\w*|Default::default\(\))\s*\)"
                          r"|unwrap_or_default\s*\(\s*\))")


def unchecked_receiver(c):
    body, name = c["body"], c["name"]
    for m in () if c["auth"] else re.finditer(r"\bself\.([\w.]+?)\.get\s*\([^;]*?\)\s*\.\s*(?:unwrap_or\s*\(\s*(?:0\w*|Default::default\(\))\s*\)"
                         r"|unwrap_or_default\s*\(\s*\))", body):
        var = re.search(r"let\s+(?:mut\s+)?(\w+)\s*(?::[^=;]+)?=\s*$", body[max(0, m.start() - 80):m.start()])
        guarded = var and re.search(rf"\b{var.group(1)}\s*(?:>|!=|==)\s*0", body)
        if not guarded and re.search(rf"\bself\.{re.escape(m.group(1))}\.\s*insert\s*\(", body):
            return [_hit(c, "auto_register_receiver", "unchecked_receiver", "medium",
                         f"unregistered account defaults to 0 and is inserted into `self.{m.group(1)}`: "
                         "receiver registered without storage payment", m.start())]
    if not c["auth"] and c["file_src"] and re.search(r"\.\s*insert\s*\(", body):
        bodies = _file_fn_bodies(c["file_src"])
        for m in re.finditer(r"\bself\.(\w+)\s*\(", body):
            d = DEFAULT_ZERO.search(bodies.get(m.group(1), "")) if m.group(1) != name else None
            if d and re.search(rf"\bself\.{re.escape(d.group(1))}\.\s*insert\s*\(", body):
                return [_hit(c, "auto_register_receiver", "unchecked_receiver", "medium",
                             f"`{m.group(1)}` defaults unregistered accounts to 0 and this method inserts them: "
                             "receiver registered without storage payment", m.start())]
    if "transfer" in name and "resolve" not in name and re.search(r"\b(?:receiver\w*|recipient\w*|to)\s*:", c["sig"]) \
            and (re.search(r"\b(?:sender\w*|from)\s*:", c["sig"]) or c["uses_pred"]):
        moves = len(re.findall(r"internal_withdraw|internal_deposit|-=|\+=|checked_sub|checked_add", body))
        checked = re.search(r"(?:sender|from|predecessor|owner)\w*(?:\(\))?\s*(?:!=|==)\s*&?\s*\*?\w*(?:receiver|recipient|to\b)"
                            r"|(?:receiver|recipient|\bto)\w*\s*(?:!=|==)\s*&?\s*\*?(?:env::)?\w*(?:sender|from|predecessor|owner)"
                            r"|assert_ne!", body)
        if moves >= 2 and not checked:
            return [_hit(c, "self_transfer", "unchecked_receiver", "medium",
                         "transfer does not reject sender == receiver (self-transfer can mint balance)")]
    return []


def gas_dos(c):
    body, out = c["body"], []
    if c["entry"] and c["mut"] and not c["private"]:
        for m in LOOP_SELF.finditer(body):
            tail = m.group("tail") or m.group("tail2") or m.group("tail3") or ""
            if not PAGINATION.search(tail) and not PAGINATION.search(c["sig"]):
                out.append(_hit(c, "unbounded_loop", "gas_dos", "low",
                                "loop over a contract collection with no bound; a growing collection can exhaust gas",
                                m.start()))
                break
    gas_checked = re.search(r"prepaid_gas\(\)\s*(?:>|>=|<|<=)|(?:>|>=|<|<=)\s*(?:env::)?prepaid_gas\(\)", body)
    static_only = "with_static_gas" in body and not re.search(r"prepaid_gas\(\)\s*-", body)
    if c["name"].endswith("transfer_call") and THEN.search(body) and not gas_checked and not static_only:
        out.append(_hit(c, "prepaid_gas_unchecked", "gas_dos", "medium",
                        "transfer_call schedules a receiver call and callback without checking prepaid gas"))
    return out


def oracle_price(c):
    body, sig = c["body"], c["sig"]
    if c["entry"] and c["mut"] and not c["auth"]:
        for p in re.findall(r"\b(\w*(?:price|exchange_rate)\w*)\s*:", sig):
            m = re.search(rf"\b{p}\b(?:\.\w+|\(\))*\s*[*/]|[*/]\s*\b{p}\b", body)
            if m:
                return [_hit(c, "caller_supplied_price", "oracle_price", "high",
                             f"price `{p}` comes from the caller and is used in value math", m.start())]
    if (ORACLE_SIG.search(sig) or "oracle" in c["name"]) and re.search(r"\bprice", body) \
            and re.search(r"[\w)\]]\s*[*/]\s*[\w(]", body) and not FRESHNESS.search(body):
        return [_hit(c, "stale_price", "oracle_price", "medium",
                     "oracle price is used without a freshness (timestamp/recency) check")]
    return []


def logic_error(c):
    body, out = c["body"], []
    m = RANDOMNESS.search(body)
    if m and (c["writes"] or "transfer" in body):
        out.append(_hit(c, "block_randomness", "logic_error", "low",
                        "block timestamp/height/random_seed used as randomness that decides value", m.start()))
    if c["mut"]:
        for mm in re.finditer(r"let\s+mut\s+(\w+)\s*(?::[^=;]+)?=\s*self(?:\s*\.\s*\w+)+?\s*\.\s*get\s*\(", body):
            v = re.escape(mm.group(1))
            rest = body[mm.end():]
            changed = re.search(rf"\b{v}\.[\w.]+\s*(?:[+\-*/]?=)(?!=)|(?<![\w.])\b{v}\s*[+\-*/]?=(?!=)|\b{v}\.\w*(?:push|insert|remove|add|sub)\w*\s*\(",
                                rest)
            saved = re.search(rf"\.\s*(?:insert|set|replace)\s*\(|[(,]\s*&?\s*(?:mut\s+)?{v}\s*[,)]|\b{v}\s*\}}\s*$", rest)
            if changed and not saved:
                out.append(_hit(c, "unsaved_changes", "logic_error", "medium",
                                f"`{mm.group(1)}` is read from a collection and modified but never written back",
                                mm.end() + changed.start()))
                break
    return out


DETECTORS = (non_private_callback, unhandled_promise_result, async_reentrancy, missing_access_control,
             missing_one_yocto, signer_auth, unguarded_upgrade, unsafe_arithmetic, precision_rounding,
             storage_staking, ft_receiver_trust, unchecked_receiver, gas_dos, oracle_price, logic_error)


def detect_ctx(ctx: dict) -> list[dict]:
    return [h for d in DETECTORS for h in d(ctx)]


def detect(fn: dict, file_src: str | None = None) -> list[dict]:
    """Detector hits for one function: [{detector, vuln_class, line, message, severity}]. Never raises."""
    if fn.get("is_test"):
        return []
    try:
        return detect_ctx(context(fn, file_src))
    except Exception:
        return []


def overflow_checks_enabled(cargo_toml: str) -> bool:
    """True when the manifest's [profile.release] sets overflow-checks = true (Rust's release default is off, so
    unchecked `+ - *` on amounts wraps silently). A workspace member without a profile inherits the root's."""
    m = re.search(r"^\s*\[profile\.release\]\s*$(.*?)(?=^\s*\[|\Z)", cargo_toml, re.M | re.S)
    return bool(m and re.search(r"^\s*overflow-checks\s*=\s*true\s*(?:#.*)?$", m.group(1), re.M))
