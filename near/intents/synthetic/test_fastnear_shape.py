"""The sandbox-to-FastNEAR converter, checked on recorded sandbox responses and a real FastNEAR record."""

import base64
import gzip
import json
import unittest
from pathlib import Path

from near.intents.synthetic.fastnear_shape import to_fastnear

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name):
    d = json.loads((FIXTURES / name).read_text())
    return d["status"], d["blocks"]


def _key_paths(obj, prefix=""):
    """Set of key paths, with list items merged, e.g. 'receipts[].receipt.receipt_id'."""
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(prefix + "." + k)
            out |= _key_paths(v, prefix + "." + k)
    elif isinstance(obj, list):
        for v in obj:
            out |= _key_paths(v, prefix + "[]")
    return out


class ShapeTest(unittest.TestCase):
    def setUp(self):
        self.status, self.blocks = _load("sandbox_exploit_log_overflow.json")
        self.tx = to_fastnear(self.status, self.blocks)
        self.real = json.loads((FIXTURES / "fastnear_exploit_record.json").read_text())

    def test_has_every_key_path_of_a_real_fastnear_record(self):
        def structural(paths):
            # function-call specific keys only; action/status variants differ between transactions
            return {p for p in paths if ".status." not in p and ".actions[]." not in p and ".metadata." not in p
                    and not p.endswith(".data")}
        missing = structural(_key_paths(self.real)) - _key_paths(self.tx)
        self.assertEqual(missing, set())

    def test_transaction_and_outcome(self):
        t = self.tx["transaction"]
        self.assertEqual(t["hash"], self.status["transaction"]["hash"])
        self.assertEqual(t["actions"][0]["FunctionCall"]["method_name"], "mt_batch_transfer_call")
        eo = self.tx["execution_outcome"]
        self.assertEqual(eo["id"], t["hash"])
        self.assertIsInstance(eo["block_height"], int)
        self.assertIsInstance(eo["block_timestamp"], int)
        self.assertNotIn("proof", eo)

    def test_every_receipt_outcome_is_kept_in_block_order(self):
        ids = [r["receipt"]["receipt_id"] for r in self.tx["receipts"]]
        self.assertEqual(sorted(ids), sorted(ro["id"] for ro in self.status["receipts_outcome"]))
        heights = [r["execution_outcome"]["block_height"] for r in self.tx["receipts"]]
        self.assertEqual(heights, sorted(heights))
        for r in self.tx["receipts"]:
            self.assertEqual(r["receipt"]["receipt_id"], r["execution_outcome"]["id"])

    def test_resolve_deposit_failure_is_preserved(self):
        failures = [r for r in self.tx["receipts"]
                    if "Failure" in r["execution_outcome"]["outcome"]["status"]]
        methods = [a["FunctionCall"]["method_name"] for r in failures
                   for a in r["receipt"]["receipt"]["Action"]["actions"]]
        self.assertEqual(methods, ["mt_resolve_deposit"])

    def test_data_receipts_follow_the_promise_chain(self):
        # the receiver's refunds go to intents.near; intents' answer to the token is null because the resolve failed
        by_receiver = {d["receiver_id"]: d for d in self.tx["data_receipts"]}
        to_token = by_receiver["omni.bridge.near"]
        self.assertEqual(to_token["predecessor_id"], "intents.near")
        self.assertIsNone(to_token["receipt"]["Data"]["data"])
        to_intents = by_receiver["intents.near"]
        refunds = json.loads(base64.b64decode(to_intents["receipt"]["Data"]["data"]))
        self.assertEqual(len(refunds), 98)
        self.assertEqual(refunds[0], str(10**36))

    def test_successful_chain_forwards_final_value(self):
        status, blocks = _load("sandbox_notify_accept.json")
        tx = to_fastnear(status, blocks)
        to_token = [d for d in tx["data_receipts"] if d["receiver_id"] == "omni.bridge.near"][0]
        self.assertEqual(json.loads(base64.b64decode(to_token["receipt"]["Data"]["data"])), ["0"])


if __name__ == "__main__":
    unittest.main()
