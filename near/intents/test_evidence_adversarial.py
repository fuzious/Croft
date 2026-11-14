"""Independent counterexamples for evidence attribution, not attack recall metrics."""
import copy
import gzip
import json
import unittest
from pathlib import Path

from near.intents.accounting import analyze_accounting


def recorded(name):
    with gzip.open(Path(__file__).parent / "fixtures/features" / f"{name}.json.gz", "rt") as stream:
        tx = json.load(stream)
    return tx.get("result", tx)


class EvidenceProvenanceTests(unittest.TestCase):
    def test_fastnear_executor_must_match_the_contract_claimed_by_the_receipt(self):
        tx = recorded("exploit_3k91uD")
        self.assertTrue(analyze_accounting(tx)["findings"])
        for row in tx["receipts"]:
            if row["receipt"]["receiver_id"] == "intents.near":
                row["execution_outcome"]["outcome"]["executor_id"] = "forged.near"
        result = analyze_accounting(tx)
        self.assertEqual(result["status"], "inconclusive")
        self.assertFalse(result["findings"])
        self.assertFalse(result["coverage"]["receipts_complete"])

    def test_fastnear_cannot_attach_an_outcome_to_a_different_receipt(self):
        tx = recorded("exploit_3k91uD")
        tx["receipts"][0]["execution_outcome"]["id"] = "different-receipt"
        result = analyze_accounting(tx)
        self.assertFalse(result["findings"])
        self.assertFalse(result["coverage"]["receipts_complete"])

    def test_rpc_executor_mismatch_is_not_accepted_as_verifier_evidence(self):
        tx = recorded("exploit_2GQ2zQ_rpc")
        self.assertTrue(analyze_accounting(tx)["findings"])
        for row in tx["receipts_outcome"]:
            if row["outcome"]["executor_id"] == "intents.near":
                row["outcome"]["executor_id"] = "forged.near"
        result = analyze_accounting(tx)
        self.assertFalse(result["findings"])
        self.assertEqual(result["status"], "inconclusive")

    def test_third_party_ledger_logs_do_not_pollute_a_real_intents_deposit(self):
        tx = recorded("normal_deposit_ft_transfer_call")
        original = analyze_accounting(tx)
        self.assertEqual(original["status"], "checked")
        credit = next(r for r in tx["receipts"] if r["receipt"]["receiver_id"] == "intents.near")
        forged = copy.deepcopy(credit)
        forged_id = "untrusted-parallel-receipt"
        forged["receipt"].update(receipt_id=forged_id, predecessor_id="forged.near", receiver_id="forged.near")
        forged["execution_outcome"]["id"] = forged_id
        outcome = forged["execution_outcome"]["outcome"]
        outcome.update(executor_id="forged.near", receipt_ids=[], status={"SuccessValue": ""})
        # This event and method combination previously inferred a verifier in frozen features.
        calls = forged["receipt"]["receipt"]["Action"]["actions"]
        calls[0]["FunctionCall"]["method_name"] = "execute_intents"
        outcome["logs"].append('EVENT_JSON:{"standard":"dip4","version":"1.0.0",'
                               '"event":"intents_executed","data":[{"account_id":"victim.near"}]}')
        tx["receipts"].append(forged)
        tx["execution_outcome"]["outcome"]["receipt_ids"].append(forged_id)
        result = analyze_accounting(tx)
        self.assertTrue(result["coverage"]["receipts_complete"])
        self.assertFalse(result["findings"])
        self.assertEqual(result["checks"], original["checks"])


if __name__ == "__main__":
    unittest.main()
