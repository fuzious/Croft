"""Convert a sandbox `EXPERIMENTAL_tx_status` result into the FastNEAR `/v0/transactions` record shape.

Field names and nesting follow real FastNEAR records (see fixtures/fastnear_exploit_record.json). What the node's RPC
does not expose is filled as follows:
- `index` and `receipt_index` (position inside the chunk) are the position inside this transaction;
- `metadata.gas_profile` is null, as FastNEAR stores it;
- `data_receipts` are rebuilt from each receipt's `output_data_receivers`: the data is the final value of the promise
  chain the receipt started (base64), or null when that chain failed. Their `receipt_id` is a stand-in derived from
  the `data_id` (the RPC does not report data receipt ids).
"""

from __future__ import annotations

import copy
import hashlib

from near.intents.synthetic.nearkeys import b58encode


def _outcome(ro: dict, blocks: dict[str, dict], index: int) -> dict:
    block = blocks[ro["block_hash"]]
    outcome = copy.deepcopy(ro["outcome"])
    outcome.setdefault("metadata", {})["gas_profile"] = None
    return {
        "block_hash": ro["block_hash"],
        "block_timestamp": int(block["timestamp"]),
        "block_height": int(block["height"]),
        "index": index,
        "id": ro["id"],
        "outcome": outcome,
    }


def _final_value(receipt_id: str, outcomes: dict[str, dict]):
    """Follow SuccessReceiptId links; return (executor of the last receipt, base64 value or None, block hash)."""
    seen = set()
    while receipt_id in outcomes and receipt_id not in seen:
        seen.add(receipt_id)
        ro = outcomes[receipt_id]
        status = ro["outcome"]["status"]
        if "SuccessReceiptId" in status:
            receipt_id = status["SuccessReceiptId"]
            continue
        value = status.get("SuccessValue") if isinstance(status, dict) else None
        return ro["outcome"]["executor_id"], value, ro["block_hash"]
    return None, None, None


def to_fastnear(status: dict, blocks: dict[str, dict]) -> dict:
    """`blocks` maps block hash to {"height", "timestamp"} (nanoseconds)."""
    tx = copy.deepcopy(status["transaction"])
    tx.setdefault("priority_fee", 0)
    tx = {k: tx[k] for k in ("signer_id", "public_key", "nonce", "receiver_id", "actions", "priority_fee",
                             "signature", "hash")}

    receipt_views = {r["receipt_id"]: r for r in status.get("receipts", [])}
    outcomes = {ro["id"]: ro for ro in status["receipts_outcome"]}

    ordered = sorted(enumerate(status["receipts_outcome"]),
                     key=lambda p: (int(blocks[p[1]["block_hash"]]["height"]), p[0]))
    receipts = []
    for index, (_, ro) in enumerate(ordered):
        view = receipt_views.get(ro["id"])
        if view is None:
            continue
        exec_outcome = _outcome(ro, blocks, index)
        receipts.append({
            "execution_outcome": exec_outcome,
            "receipt": {
                "block_height": exec_outcome["block_height"],
                "block_hash": exec_outcome["block_hash"],
                "block_timestamp": exec_outcome["block_timestamp"],
                "receipt_index": index,
                "predecessor_id": view["predecessor_id"],
                "receiver_id": view["receiver_id"],
                "receipt_id": view["receipt_id"],
                "receipt": copy.deepcopy(view["receipt"]),
                "priority": view.get("priority", 0),
            },
        })

    data_receipts = []
    for r in receipts:
        action = r["receipt"]["receipt"].get("Action")
        if not action:
            continue
        for odr in action.get("output_data_receivers", []):
            executor, value, block_hash = _final_value(r["receipt"]["receipt_id"], outcomes)
            if executor is None:
                continue
            block = blocks[block_hash]
            data_receipts.append({
                "block_height": int(block["height"]),
                "block_hash": block_hash,
                "block_timestamp": int(block["timestamp"]),
                "receipt_index": len(data_receipts),
                "predecessor_id": executor,
                "receiver_id": odr["receiver_id"],
                "receipt_id": b58encode(hashlib.sha256(b"data:" + odr["data_id"].encode()).digest()),
                "receipt": {"Data": {"data_id": odr["data_id"], "data": value, "is_promise_resume": False}},
                "priority": 0,
            })

    return {
        "transaction": tx,
        "execution_outcome": _outcome(status["transaction_outcome"], blocks, 0),
        "receipts": receipts,
        "data_receipts": data_receipts,
    }
