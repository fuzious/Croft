"""Conservative, event-based accounting for linked NEAR Intents FT/MT deposits.

Only the configured verifier can emit ledger evidence. Token evidence is scoped to
its executing contract and to the transfer-call receipt chain. This is not a state
proof, a token-value check, or a solvency calculation.

Semantics: https://github.com/near/NEPs/blob/master/neps/nep-0141.md
https://docs.near-intents.org/integration/verifier-contract/events
"""
from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter, defaultdict

from near.intents.features import KNOWN_INTENTS_IDS, _Tx

ACCOUNTING_FEATURE_KEYS = (
    "accounting_complete", "accounting_checked_flows_log", "accounting_unchecked_flows_log",
    "accounting_refund_flows_log", "accounting_excess_flows_log", "accounting_malformed_events_log",
    "accounting_max_refund_ratio", "accounting_max_excess_ratio",
)
_U128 = 2**128 - 1
_ON_TRANSFER = {"ft_on_transfer": ("nep141", "ft_resolve_transfer"),
                "mt_on_transfer": ("nep245", "mt_resolve_transfer")}
_LIMITATIONS = [
    "Checks successful emitted events in this transaction, not independently verified balances or protocol solvency.",
    "Token identity is its emitting contract; event consistency does not establish token value or honest token code.",
    "Only linked FT/MT deposit flows are checked; withdrawals, native assets and opening balances are not reconciled.",
]


def _amount(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,39}", value):
        raise ValueError("amount is not a decimal U128 string")
    value = int(value)
    if value > _U128:
        raise ValueError("amount exceeds U128")
    return value


def _account(value):
    if not isinstance(value, str) or not value:
        raise ValueError("missing account")
    return value


def _args(encoded):
    value = json.loads(base64.b64decode(encoded, validate=True))
    if not isinstance(value, dict):
        raise ValueError("call arguments are not an object")
    return value


def _input_entries(standard, args):
    if standard == "nep141":
        return Counter({(_account(args.get("sender_id")), None): _amount(args.get("amount"))})
    tokens, amounts, owners = args.get("token_ids"), args.get("amounts"), args.get("previous_owner_ids")
    if not all(isinstance(v, list) for v in (tokens, amounts, owners)) or not (len(tokens) == len(amounts) == len(owners)):
        raise ValueError("unequal token/amount/owner lists")
    entries = Counter()
    for token, amount, owner in zip(tokens, amounts, owners):
        entries[(_account(owner), _account(token))] += _amount(amount)
    return entries


def _moves(receipt):
    """Strict token events; failed-receipt logs contribute no state changes."""
    if not receipt.ok:
        return [], 0
    moves, malformed = [], 0
    for log in receipt.logs:
        if not isinstance(log, str) or not log.startswith("EVENT_JSON:"):
            continue
        try:
            event = json.loads(log[11:])
            if not isinstance(event, dict):
                raise ValueError()
            standard, name = event.get("standard"), event.get("event")
            if (standard, name) not in {(s, f"{prefix}_{kind}") for s, prefix in
                                       (("nep141", "ft"), ("nep245", "mt")) for kind in ("transfer", "mint", "burn")}:
                continue
            if event.get("version") != "1.0.0":
                raise ValueError()
            data = event.get("data")
            if not isinstance(data, list) or not data:
                raise ValueError()
            parsed = []
            for item in data:
                if not isinstance(item, dict):
                    raise ValueError()
                old = _account(item.get("old_owner_id")) if name.endswith("transfer") else (
                    _account(item.get("owner_id")) if name.endswith("burn") else None)
                new = _account(item.get("new_owner_id")) if name.endswith("transfer") else (
                    _account(item.get("owner_id")) if name.endswith("mint") else None)
                if standard == "nep141":
                    entries = [(None, _amount(item.get("amount")))]
                else:
                    tokens, amounts = item.get("token_ids"), item.get("amounts")
                    if not isinstance(tokens, list) or not isinstance(amounts, list) or len(tokens) != len(amounts) or not tokens:
                        raise ValueError()
                    entries = [(_account(t), _amount(a)) for t, a in zip(tokens, amounts)]
                parsed.extend((standard, name, old, new, token, amount) for token, amount in entries)
            moves.extend(parsed)
        except (ValueError, TypeError):
            malformed += 1
    return moves, malformed


def _coverage(tx, graph):
    tx = tx.get("result", tx)
    mismatched = False
    if "receipts_outcome" in tx:
        outcomes = [(tx.get("transaction_outcome") or {}).get("outcome") or {}]
        rows = tx.get("receipts_outcome") or []
        ids = [r.get("id") for r in rows]
        outcomes.extend(r.get("outcome") or {} for r in rows)
        bodies = tx.get("receipts") or []
        body_ids = [r.get("receipt_id") for r in bodies]
        mismatched = len(set(body_ids)) != len(body_ids) or set(body_ids) != set(ids)
        mismatched |= any((row.get("outcome") or {}).get("executor_id") != graph.receipts[row["id"]].recv for row in rows)
    else:
        outcomes = [(tx.get("execution_outcome") or {}).get("outcome") or {}]
        rows = tx.get("receipts") or []
        ids = [(r.get("receipt") or {}).get("receipt_id") for r in rows]
        outcomes.extend((r.get("execution_outcome") or {}).get("outcome") or {} for r in rows)
        mismatched = any((r.get("execution_outcome") or {}).get("id") != (r.get("receipt") or {}).get("receipt_id")
                         or ((r.get("execution_outcome") or {}).get("outcome") or {}).get("executor_id")
                         != (r.get("receipt") or {}).get("receiver_id") for r in rows)
    required, pending = set(), 0
    for outcome in outcomes:
        required.update(outcome.get("receipt_ids") or [])
        status = outcome.get("status") or {}
        if "SuccessReceiptId" in status:
            required.add(status["SuccessReceiptId"])
        pending += not any(k in status for k in ("SuccessValue", "SuccessReceiptId", "Failure"))
    missing = len(required - set(ids))
    malformed = mismatched or any(not isinstance(rid, str) or not rid for rid in ids) or len(set(ids)) != len(ids)
    malformed |= any(not r.recv or not r.pred for r in graph.order)
    # Orphan receipts cannot be used to manufacture a matching transfer chain.
    malformed |= any(r.depth == 0 for r in graph.order)
    return {"receipts_complete": bool(not missing and not pending and not malformed and ids),
            "observed_receipts": len(set(ids)), "missing_receipts": missing, "pending_outcomes": pending,
            "checked_deposit_flows": 0, "unchecked_deposit_flows": 0, "malformed_events": 0}


def _descendants(graph, root):
    seen, stack = set(), [root]
    while stack:
        rid = stack.pop()
        if rid in seen or rid not in graph.receipts:
            continue
        seen.add(rid)
        stack.extend(graph.receipts[rid].children)
    return seen


def analyze_accounting(tx: dict) -> dict:
    result = {"version": "accounting_v1", "status": "unsupported", "coverage": {},
              "checks": [], "findings": [], "limitations": list(_LIMITATIONS)}
    try:
        graph = _Tx(tx)
        coverage = _coverage(tx, graph)
    except (KeyError, ValueError, TypeError, AttributeError):
        result.update(status="inconclusive", coverage={"receipts_complete": False,
                      "checked_deposit_flows": 0, "unchecked_deposit_flows": 0, "malformed_events": 0})
        result["limitations"].append("Malformed receipt evidence could not be reconciled.")
        return result
    result["coverage"] = coverage
    parents = defaultdict(list)
    parsed = {}
    for rid, receipt in graph.receipts.items():
        parsed[rid] = _moves(receipt)
        coverage["malformed_events"] += parsed[rid][1]
        for child in receipt.children:
            parents[child].append(rid)
    for receiver_id, receiver in graph.receipts.items():
        if receiver.recv not in KNOWN_INTENTS_IDS:
            continue
        calls = [(method, args) for method, args, *_ in receiver.calls if method in _ON_TRANSFER]
        if not calls:
            continue
        check = {"kind": "deposit_backing", "status": "inconclusive", "protocol_id": receiver.recv,
                 "receiver_receipt_id": receiver_id, "owner_ids": [], "retained_credit_owners": []}
        result["checks"].append(check)
        try:
            if not coverage["receipts_complete"]:
                raise ValueError("Receipt graph is incomplete; missing burns or refunds could change the result.")
            if not receiver.ok or len(calls) != 1 or len(parents[receiver_id]) != 1:
                raise ValueError("Deposit receiver failed or its receipt linkage is ambiguous.")
            method, encoded = calls[0]
            standard, resolve_method = _ON_TRANSFER[method]
            args = _args(encoded)
            expected = _input_entries(standard, args)
            parent_id = parents[receiver_id][0]
            parent = graph.receipts[parent_id]
            check["deposit_receipt_id"] = parent_id
            if not parent.ok or parent.recv != receiver.pred or parent.recv in KNOWN_INTENTS_IDS:
                raise ValueError("No successful external token receipt is linked to this deposit.")
            peers = [rid for rid in parent.children if rid in graph.receipts
                     and graph.receipts[rid].recv == receiver.recv
                     and any(m in _ON_TRANSFER for m, *_ in graph.receipts[rid].calls)]
            if peers != [receiver_id]:
                raise ValueError("Multiple deposit receivers share the same token receipt.")
            incoming = Counter()
            for s, event, old, new, token, amount in parsed[parent_id][0]:
                if s == standard and event.endswith("transfer") and new == receiver.recv:
                    incoming[(old, token)] += amount
            if incoming != expected or not incoming or parsed[parent_id][1]:
                raise ValueError("Token transfer events do not exactly match the receiver's token/owner/amount arguments.")
            resolvers = []
            for rid in parent.children:
                r = graph.receipts.get(rid)
                if r is None or r.recv != parent.recv or r.pred != parent.recv:
                    continue
                for m, encoded_args, *_ in r.calls:
                    if m != resolve_method:
                        continue
                    body = _args(encoded_args)
                    if body.get("receiver_id") == receiver.recv and _input_entries(standard, body) == expected:
                        resolvers.append(rid)
            if len(resolvers) != 1:
                raise ValueError("No unique token resolver matches this deposit's original owners and amounts.")
            resolver_id = resolvers[0]
            if not graph.receipts[resolver_id].ok or parsed[resolver_id][1]:
                raise ValueError("Token resolution failed or its events are malformed.")
            subtree = _descendants(graph, receiver_id)
            if any(rid != receiver_id and graph.receipts[rid].recv in KNOWN_INTENTS_IDS
                   and any(m in _ON_TRANSFER for m, *_ in graph.receipts[rid].calls) for rid in subtree):
                raise ValueError("Nested deposits require separate reconciliation.")
            if any(parsed[rid][1] for rid in subtree if graph.receipts[rid].recv == receiver.recv):
                raise ValueError("Verifier accounting events are malformed or use an unsupported version.")
            deposit_by_token = Counter()
            for (_, token), amount in incoming.items():
                deposit_by_token[token] += amount
            refund = Counter()
            for s, event, old, new, token, amount in parsed[resolver_id][0]:
                if s == standard and event.endswith("transfer") and old == receiver.recv:
                    if (new, token) not in expected:
                        raise ValueError("Resolver refund owner/token does not match the original deposit.")
                    refund[token] += amount
            per_token = []
            for token, deposited in sorted(deposit_by_token.items(), key=lambda item: str(item[0])):
                token_id = f"{standard}:{parent.recv}" + (f":{token}" if token is not None else "")
                minted = burned = 0
                ledger = Counter()
                initial_owners = set()
                for rid in subtree:
                    if graph.receipts[rid].recv != receiver.recv:
                        continue
                    for s, event, old, new, tid, amount in parsed[rid][0]:
                        if s != "nep245" or tid != token_id:
                            continue
                        if event == "mt_mint":
                            minted += amount
                            ledger[new] += amount
                            initial_owners.add(new)
                        elif event == "mt_burn":
                            burned += amount
                            ledger[old] -= amount
                        elif event == "mt_transfer":
                            ledger[old] -= amount
                            ledger[new] += amount
                if not minted:
                    raise ValueError("No matching verifier credit event is available for the deposited token.")
                kept = minted - burned
                excess = max(0, kept + refund[token] - deposited)
                item = {**check, "status": "excess_credit" if excess else "balanced", "token_id": token_id,
                        "refund_receipt_id": resolver_id, "owner_ids": sorted(initial_owners),
                        "retained_credit_owners": sorted(owner for owner, amount in ledger.items() if amount > 0),
                        "deposited": str(deposited), "minted": str(minted), "burned": str(burned),
                        "refunded": str(refund[token]), "credit_retained": str(kept), "excess": str(excess),
                        "reason": "Verifier credit plus the token refund exceeds the linked deposit." if excess else
                                  "Observed verifier credit and token refund do not exceed the linked deposit."}
                per_token.append(item)
            result["checks"].pop()
            result["checks"].extend(per_token)
            coverage["checked_deposit_flows"] += 1
            for item in per_token:
                if item["status"] == "excess_credit":
                    result["findings"].append({"rule": "accounting_credit_exceeds_backing", "severity": "high",
                        "message": f"Observed credit + refund exceeds the linked {item['token_id']} deposit by {item['excess']} base units.",
                        "evidence": dict(item)})
        except (ValueError, TypeError, KeyError) as exc:
            check["reason"] = str(exc) or "Deposit evidence could not be reconciled."
            coverage["unchecked_deposit_flows"] += 1
    if result["checks"]:
        result["status"] = "inconclusive" if coverage["unchecked_deposit_flows"] else "checked"
    return result


def accounting_features(tx: dict) -> dict[str, float]:
    result = analyze_accounting(tx)
    coverage = result["coverage"]
    checked = [c for c in result["checks"] if c["status"] != "inconclusive"]
    refunds = [c for c in checked if int(c["refunded"]) > 0]
    excesses = [c for c in checked if int(c["excess"]) > 0]
    values = (float(coverage["receipts_complete"]), math.log1p(coverage["checked_deposit_flows"]),
              math.log1p(coverage["unchecked_deposit_flows"]), math.log1p(len(refunds)),
              math.log1p(len(excesses)), math.log1p(coverage["malformed_events"]),
              max((min(10.0, int(c["refunded"]) / max(1, int(c["deposited"]))) for c in checked), default=0.0),
              max((min(10.0, int(c["excess"]) / max(1, int(c["deposited"]))) for c in checked), default=0.0))
    return dict(zip(ACCOUNTING_FEATURE_KEYS, values))
