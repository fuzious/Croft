"""Receipt-graph features and invariant rules for NEAR Intents transactions.

Input is one transaction as returned by FastNEAR `/v0/transactions` (`transaction`, `execution_outcome`, `receipts`)
or by NEAR RPC `EXPERIMENTAL_tx_status` (`transaction`, `transaction_outcome`, `receipts_outcome`, `receipts`, with
or without the JSON-RPC envelope).

`tx_features` is environment-invariant: it uses structure, counts, flags, method categories and relative amounts,
never account names, heights, timestamps, hashes or absolute gas. `rule_hits` lists interpretable invariant
violations. Events from failed receipts are reverted on chain, so balance checks only use successful receipts.
"""
from __future__ import annotations

import base64
import json
import math
import re

KNOWN_INTENTS_IDS = frozenset({"intents.near", "staging-intents.near"})
LOG_LIMIT = 16384
LOG_NEAR_LIMIT = int(0.9 * LOG_LIMIT)
MANY_TOKEN_IDS = 32
DUST_MIN_ENTRIES = 16
DUST_AMOUNT = 1000

ON_TRANSFER = frozenset({"ft_on_transfer", "mt_on_transfer", "nft_on_transfer"})
EXECUTE = frozenset({"execute_intents", "simulate_intents"})
WITHDRAW = frozenset({"ft_withdraw", "mt_withdraw", "nft_withdraw", "native_withdraw"})
DEPOSIT_ENTRY = frozenset({
    "ft_transfer_call", "mt_transfer_call", "mt_batch_transfer_call", "nft_transfer_call",
    "ft_deposit", "mt_deposit_call", "verify_deposit_v2", "fin_transfer", "near_deposit",
})
ADMIN_PREFIXES = ("acl_", "pa_", "up_", "force_", "mt_force_")
ADMIN_METHODS = frozenset({
    "upgrade", "state_migrate", "pause", "unpause", "set_fee", "set_fee_collector", "update_current_salt",
    "invalidate_salts", "cleanup_nonces", "add_full_access_key", "delete_key", "add_relayer_key",
    "delete_relayer_key", "ft_force_withdraw", "nft_force_withdraw", "register_token",
})
_PRIVATE_RE = re.compile(r"(_on_transfer$|resolve|callback|^on_|^do_|^state_migrate$)")
_RESOLVE_RE = re.compile(r"_resolve_(deposit|withdraw|transfer)$|^resolve_")

RULES = {
    "failed_resolve_callback": "high",
    "log_limit": "high",
    "credit_kept": "high",
    "refund_exceeds_deposit": "medium",
    "notify_receiver_in_deposit": "medium",
    "many_token_ids": "medium",
    "private_method_direct": "medium",
    "admin_method_non_role": "medium",
    "callback_oog": "medium",
    "return_value_limit": "medium",
    "execute_intents_panic": "low",
    "unknown_method": "low",
}

FAIL_CLASSES = ("log_limit", "value_limit", "oog", "deserialize", "method_missing", "account_missing",
                "code_missing", "panic", "other")
EVENT_KEYS = (
    ("nep245", "mt_mint"), ("nep245", "mt_burn"), ("nep245", "mt_transfer"),
    ("nep141", "ft_transfer"), ("nep141", "ft_mint"), ("nep141", "ft_burn"), ("nep171", "nft_transfer"),
    ("dip4", "transfer"), ("dip4", "token_diff"), ("dip4", "intents_executed"),
)
FLOWS = ("deposit", "execute_intents", "withdrawal", "other")

FEATURE_KEYS = (
    *(f"flow_{f}" for f in FLOWS),
    "n_actions", "has_delegate", "top_args_log_bytes",
    "n_receipts_log", "n_fc_receipts_log", "n_refund_receipts_log", "max_depth",
    "n_distinct_receivers", "n_distinct_methods",
    "n_failed", "frac_failed", "first_receipt_failed", "n_failed_intents", "n_failed_callback", "n_failed_resolve",
    *(f"fail_{c}" for c in FAIL_CLASSES),
    "n_logs_log", "max_log_ratio", "total_log_kb_log", "n_events_log", "n_events_failed_log",
    *(f"ev_{s}_{e}" for s, e in EVENT_KEYS),
    "ev_dip4_withdraw", "ev_dip4_other", "ev_other_standard", "ev_unparsed",
    "max_token_ids_per_event_log", "max_dup_token_ids_log", "n_distinct_tokens_log", "dust_fraction",
    "amount_spread_log10",
    "n_self_callbacks", "n_resolve_calls", "n_on_transfer_calls", "n_notify_receivers", "n_direct_private_calls",
    "n_admin_calls", "n_admin_failed",
    "refund_over_deposit_log10", "credit_excess_log2", "refund_to_sender_frac", "max_gas_use_ratio",
)


# ---------------------------------------------------------------------------------------------------------------
# Parsing


def parse_events(logs: list[str]) -> list[dict]:
    """EVENT_JSON logs as {standard, version, event, data: list}; malformed ones as standard "unparsed"."""
    out = []
    for log in logs:
        if not log.startswith("EVENT_JSON:"):
            continue
        try:
            e = json.loads(log[11:])
            data = e.get("data")
            if isinstance(data, dict):
                data = [data]
            elif not isinstance(data, list):
                data = []
            out.append({"standard": str(e.get("standard")), "version": str(e.get("version")),
                        "event": str(e.get("event")), "data": [d for d in data if isinstance(d, dict)]})
        except (ValueError, AttributeError):
            out.append({"standard": "unparsed", "version": "", "event": "", "data": []})
    return out


class _Receipt:
    __slots__ = ("pred", "recv", "calls", "kinds", "ok", "value", "fail", "err", "logs", "children", "gas_burnt",
                 "depth", "events")

    def __init__(self):
        self.pred = self.recv = None
        self.calls = []  # (method, args_b64, gas, deposit)
        self.kinds = []
        self.ok = True
        self.value = None
        self.fail = None
        self.err = ""
        self.logs = []
        self.children = []
        self.gas_burnt = 0
        self.depth = 0
        self.events = None


def _classify_failure(failure) -> tuple[str, str]:
    s = json.dumps(failure)
    if "length of a log message" in s:
        return "log_limit", s
    if "length of a returned value" in s:
        return "value_limit", s
    if "Exceeded the prepaid gas" in s or "GasExceeded" in s or "GasLimitExceeded" in s:
        return "oog", s
    if "eserializ" in s:
        return "deserialize", s
    if "MethodResolveError" in s or "MethodNotFound" in s:
        return "method_missing", s
    if "AccountDoesNotExist" in s:
        return "account_missing", s
    if "CodeDoesNotExist" in s or "CompilationError" in s:
        return "code_missing", s
    if "panicked" in s:
        return "panic", s
    return "other", s


def _apply_outcome(r: _Receipt, o: dict) -> None:
    st = o.get("status") or {}
    r.logs = o.get("logs") or []
    r.children = o.get("receipt_ids") or []
    r.gas_burnt = o.get("gas_burnt") or 0
    if isinstance(st, dict) and "Failure" in st:
        r.ok = False
        r.fail, r.err = _classify_failure(st["Failure"])
    elif isinstance(st, dict) and "SuccessValue" in st:
        r.value = st["SuccessValue"]
    elif not isinstance(st, dict) or "SuccessReceiptId" not in st:
        r.ok = False
        r.fail, r.err = "other", json.dumps(st)


def _apply_receipt(r: _Receipt, rc: dict) -> None:
    r.pred = rc.get("predecessor_id")
    r.recv = rc.get("receiver_id")
    act = (rc.get("receipt") or {}).get("Action")
    if not act:
        r.kinds = ["Data"]
        return
    for a in act.get("actions") or []:
        if isinstance(a, dict):
            k = next(iter(a), "")
            r.kinds.append(k)
            if k == "FunctionCall":
                fc = a[k]
                r.calls.append((fc.get("method_name", ""), fc.get("args") or "", int(fc.get("gas") or 0),
                                fc.get("deposit")))
        else:
            r.kinds.append(str(a))


class _Tx:
    """Normalised receipt graph of one transaction."""

    def __init__(self, tx: dict, intents_ids=None):
        if "result" in tx and isinstance(tx["result"], dict):
            tx = tx["result"]
        t = tx.get("transaction") or {}
        self.signer = t.get("signer_id")
        self.actions = t.get("actions") or []
        self.receipts: dict[str, _Receipt] = {}
        order = []
        if "receipts_outcome" in tx:  # NEAR RPC
            root = (tx.get("transaction_outcome") or {}).get("outcome") or {}
            for ro in tx["receipts_outcome"]:
                r = self.receipts.setdefault(ro["id"], _Receipt())
                order.append(ro["id"])
                _apply_outcome(r, ro.get("outcome") or {})
            for rc in tx.get("receipts") or []:
                r = self.receipts.get(rc.get("receipt_id"))
                if r is not None:
                    _apply_receipt(r, rc)
        else:  # FastNEAR
            root = (tx.get("execution_outcome") or {}).get("outcome") or {}
            for x in tx.get("receipts") or []:
                rc = x.get("receipt") or {}
                rid = rc.get("receipt_id") or (x.get("execution_outcome") or {}).get("id")
                r = self.receipts.setdefault(rid, _Receipt())
                order.append(rid)
                _apply_receipt(r, rc)
                _apply_outcome(r, (x.get("execution_outcome") or {}).get("outcome") or {})
        self.roots = list(root.get("receipt_ids") or [])
        self.first = self.receipts.get(self.roots[0]) if self.roots else None
        self.max_depth = self._set_depths()
        self.order = [self.receipts[i] for i in order]

        self.users = {self.signer}
        self.has_delegate = False
        for a in self.actions:
            if isinstance(a, dict) and "Delegate" in a:
                self.has_delegate = True
                da = (a["Delegate"] or {}).get("delegate_action") or {}
                self.users.add(da.get("sender_id"))
        self.users.discard(None)

        for r in self.order:
            r.events = parse_events(r.logs) if r.logs else []
        ids = set(KNOWN_INTENTS_IDS) | set(intents_ids or ())
        for r in self.order:
            if any(m in EXECUTE for m, *_ in r.calls):
                ids.add(r.recv)
            for e in r.events:
                if e["standard"] == "dip4":
                    ids.add(r.recv)
                elif e["standard"] == "nep245" and e["event"] in ("mt_mint", "mt_burn"):
                    tids = e["data"][0].get("token_ids") if e["data"] else None
                    if tids and isinstance(tids[0], str) and tids[0].startswith(("nep141:", "nep245:", "nep171:")):
                        ids.add(r.recv)
        self.intents = ids
        # intents.near signs relayed transactions with its own keys; its outgoing calls are contract calls
        self.users -= ids

    def _set_depths(self) -> int:
        deepest, seen = 0, set()
        stack = [(rid, 1) for rid in self.roots]
        while stack:
            rid, d = stack.pop()
            r = self.receipts.get(rid)
            if r is None or rid in seen:
                continue
            seen.add(rid)
            r.depth = d
            deepest = max(deepest, d)
            stack.extend((c, d + 1) for c in r.children)
        return deepest

    def is_refund(self, r: _Receipt) -> bool:
        return r.pred == "system"


def _b64json(s):
    if not s:
        return None
    try:
        return json.loads(base64.b64decode(s))
    except (ValueError, TypeError):
        return None


def _int(x) -> int:
    try:
        return int(x)
    except (TypeError, ValueError):
        return 0


def _view(tx, intents_ids=None) -> _Tx:
    return tx if isinstance(tx, _Tx) else _Tx(tx, intents_ids)


# ---------------------------------------------------------------------------------------------------------------
# Flow type


def flow_type(tx, intents_ids=None) -> str:
    """deposit / execute_intents / withdrawal / other, from the methods the intents contract executed."""
    g = _view(tx, intents_ids)
    on_intents = {m for r in g.order if r.recv in g.intents for m, *_ in r.calls}
    if on_intents & EXECUTE:
        return "execute_intents"
    if on_intents & ON_TRANSFER:
        return "deposit"
    top = {a["FunctionCall"].get("method_name") for a in g.actions if isinstance(a, dict) and "FunctionCall" in a}
    if top & DEPOSIT_ENTRY:
        return "deposit"
    if on_intents & WITHDRAW:
        return "withdrawal"
    return "other"


# ---------------------------------------------------------------------------------------------------------------
# Analysis shared by features and rules


def _is_admin(method: str) -> bool:
    return method in ADMIN_METHODS or method.startswith(ADMIN_PREFIXES)


def _intents_token_id(standard: str, contract: str, tid) -> str:
    prefix = {"nep141": "nep141", "nep245": "nep245", "nep171": "nep171"}[standard]
    return f"{prefix}:{contract}" if standard == "nep141" else f"{prefix}:{contract}:{tid}"


def _token_moves(e: dict):
    """(old_owner, new_owner, token_id or None, amount) for each moved token in a nep141/245/171 event."""
    s, ev = e["standard"], e["event"]
    for d in e["data"]:
        if s == "nep141":
            old = d.get("old_owner_id") if ev == "ft_transfer" else (None if ev == "ft_mint" else d.get("owner_id"))
            new = d.get("new_owner_id") if ev == "ft_transfer" else (d.get("owner_id") if ev == "ft_mint" else None)
            yield old, new, None, _int(d.get("amount"))
        elif s in ("nep245", "nep171"):
            tids = d.get("token_ids") or []
            amts = d.get("amounts") or (["1"] * len(tids))
            if ev.endswith("_transfer"):
                old, new = d.get("old_owner_id"), d.get("new_owner_id")
            elif ev.endswith("_mint"):
                old, new = None, d.get("owner_id")
            else:
                old, new = d.get("owner_id"), None
            for i, tid in enumerate(tids):
                yield old, new, tid, _int(amts[i] if i < len(amts) else 0)


def _analyse(g: _Tx) -> dict:
    a = {
        "fail": dict.fromkeys(FAIL_CLASSES, 0), "n_failed": 0, "n_failed_intents": 0, "n_failed_callback": 0,
        "failed_resolve": [], "oog_callbacks": [], "exec_panic": [], "unknown_method": [], "value_limit": [],
        "log_limit_fail": [], "max_log": 0, "total_log": 0, "n_logs": 0, "n_events": 0, "n_events_failed": 0,
        "ev": {}, "max_tids": 0, "max_dup": 0, "tokens": set(), "dust_entries": 0, "amount_entries": 0,
        "spread": 0.0, "self_callbacks": 0, "resolve_calls": 0, "on_transfer_calls": 0, "notify": [],
        "direct_private": [], "admin": [], "refund_ratio": None, "max_gas_ratio": 0.0, "methods": set(),
        "n_fc": 0, "n_refund": 0, "big_batches": [],
    }
    minted, burned, deposited, refunded = {}, {}, {}, {}
    for r in g.order:
        if g.is_refund(r):
            a["n_refund"] += 1
        on_intents = r.recv in g.intents
        is_self = r.pred is not None and r.pred == r.recv
        direct = r.pred in g.users and not is_self
        if r.calls:
            a["n_fc"] += 1
        for method, args, gas, _dep in r.calls:
            a["methods"].add(method)
            if gas > 0:
                a["max_gas_ratio"] = max(a["max_gas_ratio"], min(r.gas_burnt / gas, 10.0))
            callback = is_self or bool(_PRIVATE_RE.search(method))
            if is_self:
                a["self_callbacks"] += 1
            if _RESOLVE_RE.search(method):
                a["resolve_calls"] += 1
            if method in ON_TRANSFER:
                a["on_transfer_calls"] += 1
                if r.pred in g.intents and not on_intents:
                    a["notify"].append(method)
            if direct and _PRIVATE_RE.search(method):
                a["direct_private"].append(method)
            if _is_admin(method) and (on_intents or direct):
                a["admin"].append((method, r.ok))
            if not r.ok:
                if is_self and _RESOLVE_RE.search(method):
                    a["failed_resolve"].append((method, r.fail))
                if r.fail == "oog" and callback and not direct:
                    a["oog_callbacks"].append((method, on_intents and bool(_RESOLVE_RE.search(method))))
                if method in EXECUTE and r.fail in ("panic", "deserialize"):
                    a["exec_panic"].append(r.fail)
                if r.fail == "method_missing" and on_intents:
                    a["unknown_method"].append(method)
            if method in ON_TRANSFER and r.ok and r.value:
                ratio = _refund_ratio(args, method, r.value)
                if ratio is not None and (a["refund_ratio"] is None or ratio > a["refund_ratio"]):
                    a["refund_ratio"] = ratio
            if method.endswith(("_transfer_call", "batch_transfer", "_deposit_call")) and direct:
                body = _b64json(args)
                if isinstance(body, dict) and isinstance(body.get("token_ids"), list):
                    _token_list_stats(a, body.get("token_ids"), body.get("amounts"))
        if not r.ok:
            a["n_failed"] += 1
            a["fail"][r.fail] += 1
            a["n_failed_intents"] += on_intents
            a["n_failed_callback"] += bool(is_self or any(_PRIVATE_RE.search(m) for m, *_ in r.calls))
            if r.fail == "log_limit":
                a["log_limit_fail"].append(r.err)
            if r.fail == "value_limit":
                a["value_limit"].append(r.err)
        for log in r.logs:
            n = len(log)
            a["n_logs"] += 1
            a["total_log"] += n
            if n > a["max_log"]:
                a["max_log"] = n
        if not r.ok:
            a["n_events_failed"] += len(r.events)
            continue
        for e in r.events:
            a["n_events"] += 1
            s, ev = e["standard"], e["event"]
            if (s, ev) in EVENT_KEYS:
                key = f"ev_{s}_{ev}"
            elif s == "dip4":
                key = "ev_dip4_withdraw" if ev.endswith("withdraw") else "ev_dip4_other"
            elif s == "unparsed":
                key = "ev_unparsed"
            else:
                key = "ev_other_standard"
            a["ev"][key] = a["ev"].get(key, 0) + 1
            if s not in ("nep141", "nep245", "nep171"):
                continue
            for d in e["data"]:
                if isinstance(d.get("token_ids"), list):
                    _token_list_stats(a, d["token_ids"], d.get("amounts"))
            for old, new, tid, amt in _token_moves(e):
                if on_intents:
                    if tid is not None:
                        a["tokens"].add(tid)
                    if ev.endswith("_mint"):
                        minted[tid] = minted.get(tid, 0) + amt
                    elif ev.endswith("_burn"):
                        burned[tid] = burned.get(tid, 0) + amt
                    continue
                try:
                    itid = _intents_token_id(s, r.recv, tid)
                except KeyError:
                    continue
                if new in g.intents and old not in g.intents:
                    deposited[itid] = deposited.get(itid, 0) + amt
                elif old in g.intents and new not in g.intents and new is not None:
                    if any(_RESOLVE_RE.search(m) for m, *_ in r.calls):
                        refunded[itid] = refunded.get(itid, 0) + amt
    # credit kept: what intents still credits plus what the token refunded must not exceed what was deposited
    a["credit"] = []
    excess_ratio, refund_frac = 0.0, 0.0
    for tid, back in refunded.items():
        dep = deposited.get(tid, 0)
        if back <= 0 or dep <= 0:
            continue
        refund_frac = max(refund_frac, min(back / dep, 10.0))
        kept = minted.get(tid, 0) - burned.get(tid, 0)
        excess = kept + back - dep
        if excess > 0 and minted.get(tid, 0) > 0:
            excess_ratio = max(excess_ratio, excess / dep)
            a["credit"].append((back, kept, dep))
    a["credit_excess"] = excess_ratio
    a["refund_frac"] = refund_frac
    return a


def _token_list_stats(a: dict, tids: list, amounts) -> None:
    n = len(tids)
    if n > a["max_tids"]:
        a["max_tids"] = n
    try:
        dup = n - len(set(tids))
    except TypeError:
        dup = 0
    if dup > a["max_dup"]:
        a["max_dup"] = dup
    amts = [_int(x) for x in amounts] if isinstance(amounts, list) else []
    pos = [x for x in amts if x > 0]
    dust = sum(1 for x in pos if x <= DUST_AMOUNT)
    spread = math.log10(max(pos)) - math.log10(min(pos)) if pos else 0.0
    if pos:
        a["amount_entries"] += len(pos)
        a["dust_entries"] += dust
        a["spread"] = max(a["spread"], spread)
    padded = n >= DUST_MIN_ENTRIES and dust >= 0.9 * n and spread >= 6
    if n >= MANY_TOKEN_IDS or padded:
        a["big_batches"].append((n, dup, dust))


def _refund_ratio(args_b64: str, method: str, value_b64: str):
    """log10(max refund_i / amount_i) asked back by an *_on_transfer receiver; None if not comparable."""
    ret = _b64json(value_b64)
    if method == "nft_on_transfer" or ret is None:
        return None
    body = _b64json(args_b64)
    if not isinstance(body, dict):
        return None
    if method == "ft_on_transfer":
        pairs = [(_int(ret), _int(body.get("amount")))]
    elif isinstance(ret, list) and isinstance(body.get("amounts"), list):
        pairs = [(_int(x), _int(y)) for x, y in zip(ret, body["amounts"])]
    else:
        return None
    best = None
    for back, amt in pairs:
        if back <= 0:
            continue
        ratio = math.log10(back) - math.log10(max(amt, 1))
        best = ratio if best is None else max(best, ratio)
    return best


# ---------------------------------------------------------------------------------------------------------------
# Public API


def _log1p(x) -> float:
    return math.log1p(x)


def tx_features(tx, intents_ids=None) -> dict[str, float]:
    g = _view(tx, intents_ids)
    a = _analyse(g)
    flow = flow_type(g)
    n = len(g.order)
    top_args = sum(len(x["FunctionCall"].get("args") or "") * 3 // 4 for x in g.actions
                   if isinstance(x, dict) and "FunctionCall" in x)
    f = {f"flow_{x}": float(flow == x) for x in FLOWS}
    f.update({
        "n_actions": float(len(g.actions)),
        "has_delegate": float(g.has_delegate),
        "top_args_log_bytes": _log1p(top_args),
        "n_receipts_log": _log1p(n),
        "n_fc_receipts_log": _log1p(a["n_fc"]),
        "n_refund_receipts_log": _log1p(a["n_refund"]),
        "max_depth": float(g.max_depth),
        "n_distinct_receivers": float(len({r.recv for r in g.order if not g.is_refund(r)})),
        "n_distinct_methods": float(len(a["methods"])),
        "n_failed": float(a["n_failed"]),
        "frac_failed": a["n_failed"] / n if n else 0.0,
        "first_receipt_failed": float(g.first is not None and not g.first.ok),
        "n_failed_intents": float(a["n_failed_intents"]),
        "n_failed_callback": float(a["n_failed_callback"]),
        "n_failed_resolve": float(len(a["failed_resolve"])),
    })
    f.update({f"fail_{c}": float(a["fail"][c]) for c in FAIL_CLASSES})
    f.update({
        "n_logs_log": _log1p(a["n_logs"]),
        "max_log_ratio": min(a["max_log"] / LOG_LIMIT, 2.0),
        "total_log_kb_log": _log1p(a["total_log"] / 1024),
        "n_events_log": _log1p(a["n_events"]),
        "n_events_failed_log": _log1p(a["n_events_failed"]),
    })
    for s, e in EVENT_KEYS:
        f[f"ev_{s}_{e}"] = _log1p(a["ev"].get(f"ev_{s}_{e}", 0))
    for k in ("ev_dip4_withdraw", "ev_dip4_other", "ev_other_standard", "ev_unparsed"):
        f[k] = _log1p(a["ev"].get(k, 0))
    ratio = a["refund_ratio"]
    f.update({
        "max_token_ids_per_event_log": _log1p(a["max_tids"]),
        "max_dup_token_ids_log": _log1p(a["max_dup"]),
        "n_distinct_tokens_log": _log1p(len(a["tokens"])),
        "dust_fraction": a["dust_entries"] / a["amount_entries"] if a["amount_entries"] else 0.0,
        "amount_spread_log10": a["spread"],
        "n_self_callbacks": float(a["self_callbacks"]),
        "n_resolve_calls": float(a["resolve_calls"]),
        "n_on_transfer_calls": float(a["on_transfer_calls"]),
        "n_notify_receivers": float(len(a["notify"])),
        "n_direct_private_calls": float(len(a["direct_private"])),
        "n_admin_calls": float(len(a["admin"])),
        "n_admin_failed": float(sum(1 for _, ok in a["admin"] if not ok)),
        "refund_over_deposit_log10": max(min(ratio, 60.0), -60.0) if ratio is not None else 0.0,
        "credit_excess_log2": math.log2(1 + min(a["credit_excess"], 1e6)),
        "refund_to_sender_frac": a["refund_frac"],
        "max_gas_use_ratio": a["max_gas_ratio"],
    })
    return f


def rule_hits(tx, intents_ids=None) -> list[dict]:
    g = _view(tx, intents_ids)
    a = _analyse(g)
    hits = []

    def hit(rule, message, severity=None):
        hits.append({"rule": rule, "severity": severity or RULES[rule], "message": message})

    if a["failed_resolve"]:
        ms = sorted({f"{m} ({c})" for m, c in a["failed_resolve"]})
        hit("failed_resolve_callback", f"resolve callback failed: {', '.join(ms)}")
    if a["max_log"] >= LOG_NEAR_LIMIT or a["log_limit_fail"]:
        why = "a receipt failed on the log length limit" if a["log_limit_fail"] else \
            f"a log of {a['max_log']} bytes is over 90% of the {LOG_LIMIT}-byte limit"
        hit("log_limit", why)
    if a["credit"]:
        back, kept, dep = max(a["credit"])
        hit("credit_kept", f"token refunded {back} to the sender while intents still credits {kept} "
                           f"of a {dep} deposit (credited + refunded > deposited)")
    if a["refund_ratio"] is not None and a["refund_ratio"] > 0:
        hit("refund_exceeds_deposit", f"an *_on_transfer receiver asked to refund 10^{a['refund_ratio']:.1f}x "
                                      f"the amount it received")
    if a["notify"] and flow_type(g) == "deposit":
        hit("notify_receiver_in_deposit", f"the deposit notified a receiver contract ({len(a['notify'])} call(s) "
                                          f"of {sorted(set(a['notify']))[0]})")
    if a["big_batches"]:
        n, dup, dust = max(a["big_batches"])
        hit("many_token_ids", f"a batch of {n} token ids ({dup} duplicates, {dust} dust amounts)")
    if a["direct_private"]:
        hit("private_method_direct", f"callback/private method called directly by the signer: "
                                     f"{', '.join(sorted(set(a['direct_private'])))}")
    if a["admin"]:
        failed = sorted({m for m, ok in a["admin"] if not ok})
        if failed:
            hit("admin_method_non_role", f"admin/role method failed for the caller: {', '.join(failed)}")
        else:
            hit("admin_method_non_role", f"admin/role method called: {', '.join(sorted({m for m, _ in a['admin']}))}",
                "low")
    if a["oog_callbacks"]:
        sev = "high" if any(crit for _, crit in a["oog_callbacks"]) else None
        hit("callback_oog", f"callback ran out of gas: {', '.join(sorted({m for m, _ in a['oog_callbacks']}))}", sev)
    if a["value_limit"]:
        hit("return_value_limit", "a receipt failed on the returned-value length limit")
    if a["exec_panic"]:
        hit("execute_intents_panic", f"execute_intents failed ({', '.join(sorted(set(a['exec_panic'])))})")
    if a["unknown_method"]:
        hit("unknown_method", f"method not found on the intents contract: "
                              f"{', '.join(sorted(set(a['unknown_method'])))}")
    return hits


# ---------------------------------------------------------------------------------------------------------------
# Measurement over local files: python -m near.intents.features --labels LABELS.jsonl PATH...


def _iter_txs(paths):
    import gzip
    from pathlib import Path

    for p in map(Path, paths):
        if p.is_dir():
            for f in sorted(p.glob("*.json")):
                try:
                    yield json.loads(f.read_text())
                except ValueError:
                    continue
            continue
        opener = gzip.open if p.suffix == ".gz" else open
        with opener(p, "rt") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)


def _tx_hash(tx: dict):
    t = tx.get("result", tx) if isinstance(tx.get("result"), dict) else tx
    return (t.get("transaction") or {}).get("hash")


def measure(paths, labels_path=None) -> dict:
    """Per-group rule hit counts. Unlabelled transactions are normals, grouped by flow type."""
    import time
    from collections import Counter, defaultdict

    labels = {}
    if labels_path:
        with open(labels_path) as fh:
            for line in fh:
                x = json.loads(line)
                labels[x["tx_hash"]] = f"{x['incident'][:10]} {x['role']}"
    counts, hits = Counter(), defaultdict(Counter)
    seen, elapsed = set(), 0.0
    for tx in _iter_txs(paths):
        h = _tx_hash(tx)
        if not h or h in seen or not (tx.get("result") or tx.get("receipts")):
            continue
        seen.add(h)
        t0 = time.perf_counter()
        g = _Tx(tx)
        flow = flow_type(g)
        tx_features(g)
        rs = rule_hits(g)
        elapsed += time.perf_counter() - t0
        groups = [labels[h]] if h in labels else ["normal (all)", f"normal {flow}"]
        sev = {"high": 3, "medium": 2, "low": 1}
        top = max((sev[r["severity"]] for r in rs), default=0)
        for grp in groups:
            counts[grp] += 1
            for r in {r["rule"] for r in rs}:
                hits[grp][r] += 1
            for name, level in (("ANY high", 3), ("ANY medium+", 2)):
                if top >= level:
                    hits[grp][name] += 1
    return {"counts": dict(counts), "hits": {k: dict(v) for k, v in hits.items()}, "n": len(seen),
            "txs_per_s": len(seen) / elapsed if elapsed else 0.0}


def _print_table(m: dict) -> None:
    cols = ["ANY high", "ANY medium+", *RULES]
    groups = sorted(m["counts"], key=lambda g: (not g.startswith("normal"), g))
    print("| rule (severity) | " + " | ".join(f"{g} (n={m['counts'][g]})" for g in groups) + " |")
    print("|---|" + "---|" * len(groups))
    for c in cols:
        label = c if c.startswith("ANY") else f"{c} ({RULES[c]})"
        cells = []
        for g in groups:
            k, n = m["hits"].get(g, {}).get(c, 0), m["counts"][g]
            cells.append(f"{k} ({100 * k / n:.2f}%)" if k else "0")
        print(f"| {label} | " + " | ".join(cells) + " |")
    print(f"\n{m['n']} unique transactions, {m['txs_per_s']:.0f} tx/s (graph + features + rules, parsed JSON in)")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--labels", help="labelled jsonl with tx_hash, incident, role")
    ap.add_argument("paths", nargs="+", help="tx jsonl(.gz) files or directories of RPC tx .json files")
    args = ap.parse_args()
    _print_table(measure(args.paths, args.labels))
