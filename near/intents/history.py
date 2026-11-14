"""Bounded, strictly earlier NEAR Intents evidence; never an account blacklist.

Raw transaction wrappers and compact summaries share the same checks. Summaries
are internal preprocessing output, not accepted as claims from an API caller.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from itertools import islice

from near.intents import features as ft

MAX_HISTORY_TRANSACTIONS = 100
HISTORY_WINDOW_SECONDS = 86400
SHARED_ACCOUNTS = ft.KNOWN_INTENTS_IDS | {"system", "meteor-relayer.near", "team.herewallet.near"}
HISTORY_FEATURE_KEYS = (
    "history_available", "history_related_log", "history_failed_callback_log",
    "history_retained_credit_log", "history_failed_private_probe_log", "history_probe_methods_log",
    "history_withdraw_after_callback", "history_withdraw_after_retained_credit",
    "history_repeated_failed_probe", "history_seconds_since_previous_log",
)
_ACCOUNT = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")


def _account(value):
    return value if isinstance(value, str) and 2 <= len(value) <= 64 and _ACCOUNT.fullmatch(value) and value not in SHARED_ACCOUNTS else None


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    try:
        n = int(value)
        return n if 0 < n < 10**22 else None
    except ValueError:
        return None


def _positive_amount(value):
    return isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 39 and 0 < int(value) < 2**128


def _unwrap(tx):
    value = tx.get("result", tx) if isinstance(tx, dict) else {}
    return value if isinstance(value, dict) else {}


def _receipt_data(tx):
    if "receipts_outcome" in tx:
        outcomes = {x["id"]: x for x in tx["receipts_outcome"]}
        return [(x, outcomes.get(x.get("receipt_id"), {})) for x in tx.get("receipts", [])]
    return [(x.get("receipt", {}), x.get("execution_outcome", {})) for x in tx.get("receipts", [])]


def _coverage(tx, g):
    root = tx.get("execution_outcome", tx.get("transaction_outcome", {}))
    start = (_number(root.get("block_height")), _number(root.get("block_timestamp")))
    heights, times = [start[0]], [start[1]]
    rows = _receipt_data(tx)
    ids, required = set(), set(g.roots)
    complete = bool(rows and g.roots)
    root_status = root.get("outcome", {}).get("status", {})
    complete &= isinstance(root_status, dict) and any(k in root_status for k in ("SuccessValue", "SuccessReceiptId", "Failure"))
    complete &= root.get("id") == (tx.get("transaction") or {}).get("hash")
    if isinstance(root_status, dict) and "SuccessReceiptId" in root_status:
        required.add(root_status["SuccessReceiptId"])
    edges = {}
    for receipt, execution in rows:
        rid = receipt.get("receipt_id")
        outcome = execution.get("outcome", {})
        status = outcome.get("status", {})
        if not rid or rid in ids or execution.get("id") != rid or outcome.get("executor_id") != receipt.get("receiver_id"):
            complete = False
        ids.add(rid)
        if not isinstance(status, dict) or not any(k in status for k in ("SuccessValue", "SuccessReceiptId", "Failure")):
            complete = False
        children = set(outcome.get("receipt_ids", []))
        if isinstance(status, dict) and "SuccessReceiptId" in status:
            children.add(status["SuccessReceiptId"])
        required.update(children)
        edges[rid] = children
        # Outcome time, not receipt creation time, prevents asynchronous lookahead.
        heights.append(_number(execution.get("block_height")))
        times.append(_number(execution.get("block_timestamp")))
    for receipt in tx.get("data_receipts", []):
        ids.add(receipt.get("receipt_id"))
        heights.append(_number(receipt.get("block_height")))
        times.append(_number(receipt.get("block_timestamp")))
    seen, queue = set(), list(g.roots)
    while queue:
        rid = queue.pop()
        if rid in seen:
            continue
        seen.add(rid)
        queue.extend(edges.get(rid, ()))
    action_ids = {r.get("receipt_id") for r, _ in rows}
    complete &= required <= ids and action_ids <= seen
    ordered = all(x is not None for x in heights + times)
    if ordered:
        ordered = min(heights) == start[0] and min(times) == start[1]
    return bool(complete), start, (max(heights), max(times)) if ordered else (None, None)


def summarize_transaction(tx: dict) -> dict:
    """Compact evidence for chronological training and account-history joins."""
    tx = _unwrap(tx)
    result = {"tx_hash": (tx.get("transaction") or {}).get("hash"), "complete": False,
              "start_height": None, "start_timestamp": None, "end_height": None, "end_timestamp": None,
              "protocols": [], "participants": [], "actors": [], "withdrawal_actors": [], "failed_callback_actors": [],
              "private_probe_methods": {}, "retained_credit_owners": []}
    try:
        g = ft._Tx(tx)
        complete, start, end = _coverage(tx, g)
        result.update(complete=complete, start_height=start[0], start_timestamp=start[1],
                      end_height=end[0], end_timestamp=end[1],
                      protocols=sorted({r.recv for r in g.order if r.recv in ft.KNOWN_INTENTS_IDS and r.calls}))
        participants, actors, withdrawn, minted = set(), set(), set(), set()
        direct = {_account(g.signer)}
        for action in g.actions:
            if isinstance(action, dict) and isinstance(action.get("Delegate"), dict):
                direct.add(_account((action["Delegate"].get("delegate_action") or {}).get("sender_id")))
        direct.discard(None)
        probes = {}
        failed_callback = False
        for r in g.order:
            if r.recv not in ft.KNOWN_INTENTS_IDS:
                continue
            methods = {m for m, *_ in r.calls}
            if r.pred in direct and r.pred != r.recv:
                # A relayer executing a signed batch is not the batch's user.
                if not methods & (ft.EXECUTE | ft.ON_TRANSFER):
                    actors.add(r.pred)
                    participants.add(r.pred)
                failed_probes = {m for m in methods if ft._PRIVATE_RE.search(m) or ft._is_admin(m)} if not r.ok else set()
                if failed_probes:
                    probes.setdefault(r.pred, set()).update(failed_probes)
                    participants.add(r.pred)
            if not r.ok:
                failed_callback |= r.pred == r.recv and any(ft._RESOLVE_RE.search(m) for m in methods)
                continue
            for event in r.events:
                for data in event["data"]:
                    if event["standard"] == "dip4" and event["event"] == "intents_executed":
                        if owner := _account(data.get("account_id")):
                            participants.add(owner)
                            actors.add(owner)
                    if event["standard"] == "dip4" and event["event"] in ft.WITHDRAW:
                        if owner := _account(data.get("account_id")):
                            participants.add(owner)
                            withdrawn.add(owner)
                    if event["standard"] != "nep245" or event["event"] not in {"mt_mint", "mt_burn"}:
                        continue
                    owner = _account(data.get("owner_id"))
                    amounts, tokens = data.get("amounts"), data.get("token_ids")
                    if not owner or not isinstance(amounts, list) or not isinstance(tokens, list) or len(amounts) != len(tokens):
                        continue
                    if not any(_positive_amount(a) for a in amounts):
                        continue
                    participants.add(owner)
                    if event["event"] == "mt_mint":
                        minted.add(owner)
                    elif data.get("memo") == "withdraw" or methods & ft.WITHDRAW:
                        withdrawn.add(owner)
        # Mint beneficiaries are context links, not authenticated initiators.
        result.update(participants=sorted(participants), actors=sorted(actors), withdrawal_actors=sorted(withdrawn),
                      failed_callback_actors=sorted(minted | actors) if failed_callback else [],
                      private_probe_methods={k: sorted(v) for k, v in sorted(probes.items())})
        if complete:
            from near.intents.accounting import analyze_accounting
            report = analyze_accounting(tx)
            owners = set()
            for finding in report.get("findings", []):
                if finding.get("rule") == "accounting_credit_exceeds_backing" and finding.get("severity") == "high":
                    owners.update(x for x in finding.get("evidence", {}).get("retained_credit_owners", []) if _account(x))
            result["retained_credit_owners"] = sorted(owners)
            result["participants"] = sorted(participants | owners)
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
        result["complete"] = False
        result["participants"] = []
    return result


def analyze_history_summaries(target: dict, priors) -> dict:
    """Use only summaries made by summarize_transaction, not externally supplied claims."""
    candidates = list(islice(priors, MAX_HISTORY_TRANSACTIONS + 1))
    excluded = Counter(dict.fromkeys(("duplicate", "unknown_order", "not_strictly_earlier", "outside_window", "incomplete", "unrelated"), 0))
    coverage = {"input_transactions": len(candidates), "inspected_transactions": min(len(candidates), MAX_HISTORY_TRANSACTIONS),
                "input_truncated": len(candidates) > MAX_HISTORY_TRANSACTIONS, "eligible_prior_transactions": 0,
                "related_transactions": 0, "excluded": excluded, "max_transactions": MAX_HISTORY_TRANSACTIONS,
                "window_seconds": HISTORY_WINDOW_SECONDS, "complete_history": False}
    out = {"status": "unavailable", "scope": "bounded_earlier_transactions", "target_participants": target["participants"],
           "coverage": coverage, "related_transactions": [], "findings": [],
           "limitations": ["Only supplied earlier transactions within one day are inspected; this is not complete account history.",
                           "Shared accounts establish context, not ownership, malicious intent or a trace of stolen funds."]}
    order = (target.get("start_height"), target.get("start_timestamp"))
    if not target.get("complete") or not target.get("tx_hash") or not target["participants"] or None in order or len(target["protocols"]) != 1:
        out["limitations"].append("Target receipt coverage, chronological position, single-protocol scope or attributable participant is unavailable.")
        return out
    seen = {target["tx_hash"]}
    participants = set(target["participants"])
    for prior in candidates[:MAX_HISTORY_TRANSACTIONS]:
        h = prior.get("tx_hash")
        if not h or h in seen:
            excluded["duplicate"] += 1
            continue
        seen.add(h)
        end = (prior.get("end_height"), prior.get("end_timestamp"))
        if None in end:
            excluded["unknown_order"] += 1
            continue
        if not (end[0] < order[0] and end[1] < order[1]):
            excluded["not_strictly_earlier"] += 1
            continue
        if order[1] - end[1] > HISTORY_WINDOW_SECONDS * 10**9:
            excluded["outside_window"] += 1
            continue
        if not prior.get("complete"):
            excluded["incomplete"] += 1
            continue
        coverage["eligible_prior_transactions"] += 1
        shared = participants & set(prior["participants"])
        if not shared or prior["protocols"] != target["protocols"]:
            excluded["unrelated"] += 1
            continue
        observations = []
        callback = shared & set(prior["failed_callback_actors"])
        retained = shared & set(prior["retained_credit_owners"])
        probes = {account: methods for account, methods in prior["private_probe_methods"].items() if account in shared}
        if callback:
            observations.append("prior_failed_callback")
        if retained:
            observations.append("prior_retained_credit")
        if probes:
            observations.append("prior_failed_private_probe")
        out["related_transactions"].append({"tx_hash": h, "block_height": prior["start_height"],
            "block_timestamp": prior["start_timestamp"], "end_timestamp": end[1], "shared_accounts": sorted(shared),
            "observations": observations, "failed_callback_accounts": sorted(callback), "retained_credit_accounts": sorted(retained),
            "private_probe_methods": probes})
    related = out["related_transactions"]
    related.sort(key=lambda r: (r["block_height"], r["block_timestamp"], r["tx_hash"]), reverse=True)
    coverage["related_transactions"] = len(related)
    out["status"] = "available" if related else "no_prior_evidence"
    withdrawals = set(target["withdrawal_actors"])
    for key, code, description in (("failed_callback_accounts", "history_withdrawal_after_callback", "a failed deposit or withdrawal callback"),
                                    ("retained_credit_accounts", "history_withdrawal_after_retained_credit", "a reported retained-credit discrepancy")):
        linked = [r for r in related if withdrawals & set(r[key])]
        if linked:
            accounts = sorted(withdrawals & {a for r in linked for a in r[key]})
            out["findings"].append({"rule": code, "severity": "low", "accounts": accounts,
                "transaction_hashes": [r["tx_hash"] for r in linked],
                "message": f"This withdrawal involves an account linked to {description} in earlier supplied transactions. "
                           "Opening balances and intervening transfers are unknown; this does not establish that the withdrawal spent unbacked credit."})
    for actor in target["private_probe_methods"]:
        linked = [r for r in related if actor in r["private_probe_methods"] and order[1] - r["end_timestamp"] <= 3600 * 10**9]
        if len(linked) >= 2:
            out["findings"].append({"rule": "history_repeated_failed_private_probes", "severity": "medium", "accounts": [actor],
                "transaction_hashes": [r["tx_hash"] for r in linked],
                "message": "The same direct caller made at least three failed private/admin calls within one hour, including this transaction. "
                           "This is repeated probing evidence, not proof of a successful exploit."})
    return out


def history_features_from_summaries(target: dict, priors) -> dict[str, float]:
    report = analyze_history_summaries(target, priors)
    rows = report["related_transactions"]
    rules = {f["rule"] for f in report["findings"]}
    methods = {m for r in rows for ms in r["private_probe_methods"].values() for m in ms}
    age = (target["start_timestamp"] - max(r["end_timestamp"] for r in rows)) / 10**9 if rows else 0
    values = (bool(rows), math.log1p(len(rows)), math.log1p(sum(bool(r["failed_callback_accounts"]) for r in rows)),
              math.log1p(sum(bool(r["retained_credit_accounts"]) for r in rows)),
              math.log1p(sum(bool(r["private_probe_methods"]) for r in rows)), math.log1p(len(methods)),
              "history_withdrawal_after_callback" in rules, "history_withdrawal_after_retained_credit" in rules,
              "history_repeated_failed_private_probes" in rules, math.log1p(age))
    return dict(zip(HISTORY_FEATURE_KEYS, map(float, values)))


def analyze_history(target_tx: dict, prior_txs) -> dict:
    return analyze_history_summaries(summarize_transaction(target_tx),
                                    (summarize_transaction(tx) for tx in islice(prior_txs, MAX_HISTORY_TRANSACTIONS + 1)))


def history_features(target_tx: dict, prior_txs) -> dict[str, float]:
    return history_features_from_summaries(summarize_transaction(target_tx),
                                         (summarize_transaction(tx) for tx in islice(prior_txs, MAX_HISTORY_TRANSACTIONS + 1)))
