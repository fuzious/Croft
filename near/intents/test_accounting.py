"""Accounting invariants on recorded transactions and explicit counterexamples."""
import base64
import copy
import gzip
import json
import math
import unittest
from pathlib import Path

from near.intents.accounting import ACCOUNTING_FEATURE_KEYS, accounting_features, analyze_accounting

FIX = Path(__file__).parent / "fixtures/features"


def fixture(name):
    with gzip.open(FIX / f"{name}.json.gz", "rt") as stream:
        return json.load(stream)


def event(standard, name, data):
    return 'EVENT_JSON:' + json.dumps({"standard": standard, "version": "1.0.0", "event": name, "data": [data]})


def transfer(old, new, amount):
    return event("nep141", "ft_transfer", {"old_owner_id": old, "new_owner_id": new, "amount": str(amount)})


def ledger(name, amount, owner="alice.near", token="nep141:token.near"):
    return event("nep245", name, {"owner_id": owner, "token_ids": [token], "amounts": [str(amount)]})


def receipt(rid, pred, recv, method, args, logs=(), children=(), failed=False):
    return {"receipt": {"receipt_id": rid, "predecessor_id": pred, "receiver_id": recv,
                        "receipt": {"Action": {"actions": [{"FunctionCall": {
                            "method_name": method, "args": base64.b64encode(json.dumps(args).encode()).decode(),
                            "gas": 1, "deposit": "0"}}]}}},
            "execution_outcome": {"id": rid, "outcome": {"executor_id": recv, "receipt_ids": list(children), "logs": list(logs),
                "status": {"Failure": {"error": "reverted"}} if failed else {"SuccessValue": ""}}}}


def deposit(amount=100, refunded=0, burned=0, burn_failed=False):
    args = {"sender_id": "alice.near", "amount": str(amount), "msg": ""}
    tx = {"transaction": {"hash": "tx", "signer_id": "alice.near", "receiver_id": "token.near", "actions": []},
          "execution_outcome": {"outcome": {"receipt_ids": ["deposit"], "status": {"SuccessReceiptId": "deposit"}}},
          "receipts": [
              receipt("deposit", "alice.near", "token.near", "ft_transfer_call", {},
                      [transfer("alice.near", "intents.near", amount)], ["credit", "refund"]),
              receipt("credit", "token.near", "intents.near", "ft_on_transfer", args,
                      [ledger("mt_mint", amount)], ["burn"]),
              receipt("burn", "intents.near", "intents.near", "ft_resolve_deposit", {},
                      [ledger("mt_burn", burned)] if burned else [], failed=burn_failed),
              receipt("refund", "token.near", "token.near", "ft_resolve_transfer",
                      {"sender_id": "alice.near", "receiver_id": "intents.near", "amount": str(amount)},
                      [transfer("intents.near", "alice.near", refunded)] if refunded else []),
          ]}
    return tx


class RealAccountingTests(unittest.TestCase):
    def test_recorded_exploit_links_refund_to_retained_verifier_credit(self):
        for name in ("exploit_2GQ2zQ", "exploit_3k91uD"):
            result = analyze_accounting(fixture(name))
            self.assertEqual(result["status"], "checked")
            self.assertTrue(result["findings"])
            for finding in result["findings"]:
                self.assertEqual(finding["severity"], "high")
                evidence = finding["evidence"]
                self.assertGreater(int(evidence["excess"]), 0)
                self.assertEqual(int(evidence["credit_retained"]) + int(evidence["refunded"]) -
                                 int(evidence["deposited"]), int(evidence["excess"]))
                self.assertTrue(evidence["retained_credit_owners"])

    def test_normal_deposits_and_refunded_oog_attempt_are_consistent(self):
        for name in ("normal_deposit_ft_transfer_call", "normal_deposit_mt_deposit_call", "april_oog_self_callback"):
            result = analyze_accounting(fixture(name))
            self.assertEqual(result["status"], "checked", name)
            self.assertFalse(result["findings"], name)
            self.assertTrue(all(c["status"] == "balanced" for c in result["checks"]))

    def test_rpc_shape_matches_fastnear(self):
        self.assertEqual(analyze_accounting(fixture("exploit_2GQ2zQ")),
                         analyze_accounting(fixture("exploit_2GQ2zQ_rpc")))

    def test_withdrawal_without_token_logs_is_not_a_backing_violation(self):
        result = analyze_accounting(fixture("normal_withdrawal_ft_withdraw"))
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["findings"], [])

    def test_fixed_feature_schema_is_finite_for_every_fixture(self):
        for path in FIX.glob("*.json.gz"):
            result = accounting_features(fixture(path.name.removesuffix(".json.gz")))
            self.assertEqual(tuple(result), ACCOUNTING_FEATURE_KEYS)
            self.assertTrue(all(isinstance(x, float) and math.isfinite(x) for x in result.values()))


class AccountingCounterexamples(unittest.TestCase):
    def test_one_base_unit_excess_survives_u128_size_without_float_rounding(self):
        tx = deposit(2**128 - 1, refunded=1)
        result = analyze_accounting(tx)
        self.assertEqual(result["findings"][0]["evidence"]["excess"], "1")
        self.assertEqual(result["checks"][0]["deposited"], str(2**128 - 1))

    def test_refund_burns_balance_but_failed_burn_logs_do_not(self):
        self.assertFalse(analyze_accounting(deposit(refunded=40, burned=40))["findings"])
        failed = analyze_accounting(deposit(refunded=40, burned=40, burn_failed=True))
        self.assertEqual(failed["findings"][0]["evidence"]["excess"], "40")
        self.assertEqual(failed["findings"][0]["evidence"]["burned"], "0")

    def test_partial_graph_cannot_prove_a_retained_credit(self):
        tx = deposit(refunded=100, burned=100)
        tx["receipts"] = [r for r in tx["receipts"] if r["receipt"]["receipt_id"] != "burn"]
        result = analyze_accounting(tx)
        self.assertFalse(result["findings"])
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["coverage"]["missing_receipts"], 1)

    def test_malformed_amount_or_mismatched_batch_cannot_silently_become_zero(self):
        for amount in ("-1", "1.0", str(2**128), True, None):
            tx = deposit(refunded=100)
            tx["receipts"][1]["execution_outcome"]["outcome"]["logs"] = [ledger("mt_mint", amount)]
            result = analyze_accounting(tx)
            self.assertFalse(result["findings"])
            self.assertEqual(result["status"], "inconclusive")

    def test_a_third_party_cannot_become_the_verifier_by_emitting_its_events(self):
        tx = json.loads(json.dumps(deposit(refunded=100)).replace("intents.near", "forged.near"))
        self.assertEqual(analyze_accounting(tx)["status"], "unsupported")
        self.assertEqual(analyze_accounting(tx)["findings"], [])

    def test_wrong_refund_owner_or_token_does_not_match_the_original_deposit(self):
        tx = deposit(refunded=100)
        tx["receipts"][-1]["execution_outcome"]["outcome"]["logs"] = [transfer("intents.near", "bob.near", 100)]
        self.assertEqual(analyze_accounting(tx)["status"], "inconclusive")
        self.assertFalse(analyze_accounting(tx)["findings"])
        tx = deposit(refunded=100)
        tx["receipts"][1]["execution_outcome"]["outcome"]["logs"] = [ledger("mt_mint", 100, token="nep141:other.near")]
        self.assertFalse(analyze_accounting(tx)["findings"])

    def test_unrelated_branch_cannot_supply_credit_or_refund_evidence(self):
        tx = deposit(refunded=0)
        tx["execution_outcome"]["outcome"]["receipt_ids"].append("unrelated")
        tx["receipts"].append(receipt("unrelated", "intents.near", "intents.near", "ft_resolve_withdraw", {},
                                      [ledger("mt_mint", 500)]))
        result = analyze_accounting(tx)
        self.assertFalse(result["findings"])
        self.assertEqual(result["checks"][0]["minted"], "100")

    def test_internal_transfers_update_observed_beneficiary_without_creating_backing(self):
        tx = deposit(refunded=100)
        tx["receipts"][2]["execution_outcome"]["outcome"]["logs"] = [event("nep245", "mt_transfer", {
            "old_owner_id": "alice.near", "new_owner_id": "bob.near", "token_ids": ["nep141:token.near"], "amounts": ["100"]})]
        result = analyze_accounting(tx)
        self.assertEqual(result["findings"][0]["evidence"]["retained_credit_owners"], ["bob.near"])

    def test_duplicate_receipt_ids_are_inconclusive(self):
        tx = deposit(refunded=100)
        tx["receipts"].append(copy.deepcopy(tx["receipts"][1]))
        self.assertFalse(analyze_accounting(tx)["findings"])
        self.assertFalse(analyze_accounting(tx)["coverage"]["receipts_complete"])


if __name__ == "__main__":
    unittest.main()
