"""History must not leak future receipts or blame shared relayers/recipients."""
import base64
import gzip
import json
import math
import unittest
from pathlib import Path
from unittest.mock import patch

from near.intents import history as h

FIXTURES = Path(__file__).parent / "fixtures/features"


def fixture(name):
    with gzip.open(FIXTURES / f"{name}.json.gz", "rt") as f:
        return json.load(f)


def event(kind, **data):
    return "EVENT_JSON:" + json.dumps({"standard": "nep245", "event": kind, "version": "1.0.0", "data": [data]})


def transaction(tx_hash, height, *, actor="alice.near", method="upgrade", failure=True, logs=(), receiver="intents.near"):
    rid = tx_hash + "-receipt"
    args = base64.b64encode(b"{}").decode()
    call = {"FunctionCall": {"method_name": method, "args": args, "gas": 100, "deposit": "0"}}
    outcome = {"executor_id": receiver, "receipt_ids": [], "logs": list(logs),
               "status": {"Failure": {"ActionError": "private method"}} if failure else {"SuccessValue": ""}}
    return {"transaction": {"hash": tx_hash, "signer_id": actor, "receiver_id": receiver, "actions": [call]},
            "execution_outcome": {"id": tx_hash, "block_height": height, "block_timestamp": height * 10**9,
                "outcome": {"executor_id": actor, "receipt_ids": [rid], "logs": [], "status": {"SuccessReceiptId": rid}}},
            "receipts": [{"receipt": {"receipt_id": rid, "predecessor_id": actor, "receiver_id": receiver,
                "block_height": height + 1, "block_timestamp": (height + 1) * 10**9,
                "receipt": {"Action": {"actions": [call]}}},
                "execution_outcome": {"id": rid, "block_height": height + 1, "block_timestamp": (height + 1) * 10**9,
                                      "outcome": outcome}}]}


class ChronologyTest(unittest.TestCase):
    def test_future_same_block_unknown_and_self_are_excluded(self):
        target = transaction("target", 200)
        old = transaction("old", 190)
        same = transaction("same", 199)  # receipt executes in target block
        future = transaction("future", 201)
        unknown = transaction("unknown", 180)
        del unknown["receipts"][0]["execution_outcome"]["block_timestamp"]
        report = h.analyze_history(target, [target, future, same, unknown, old])
        self.assertEqual([r["tx_hash"] for r in report["related_transactions"]], ["old"])
        self.assertEqual(report["coverage"]["excluded"]["not_strictly_earlier"], 2)
        self.assertEqual(report["coverage"]["excluded"]["unknown_order"], 1)
        self.assertEqual(report["coverage"]["excluded"]["duplicate"], 1)

    def test_earlier_root_with_later_outcome_never_leaks(self):
        prior = transaction("prior", 190)
        prior["receipts"][0]["execution_outcome"].update(block_height=205, block_timestamp=205 * 10**9)
        target = transaction("target", 200)
        report = h.analyze_history(target, [prior])
        self.assertEqual(report["status"], "no_prior_evidence")
        self.assertEqual(report["coverage"]["excluded"]["not_strictly_earlier"], 1)
        self.assertEqual(h.history_features(target, [prior])["history_failed_private_probe_log"], 0)

    def test_partial_or_unknown_target_is_unavailable(self):
        for missing in ("receipt", "time"):
            target = transaction("target", 200)
            if missing == "receipt":
                target["receipts"][0]["execution_outcome"]["outcome"]["receipt_ids"] = ["missing"]
            else:
                del target["execution_outcome"]["block_height"]
            report = h.analyze_history(target, [transaction("prior", 180)])
            self.assertEqual(report["status"], "unavailable")
            self.assertFalse(report["findings"])

    def test_missing_root_success_pointer_and_wrong_root_id_are_incomplete(self):
        for field in ("pointer", "id"):
            target = transaction("target", 200)
            if field == "pointer":
                target["execution_outcome"]["outcome"]["status"] = {"SuccessReceiptId": "missing"}
            else:
                target["execution_outcome"]["id"] = "another-transaction"
            self.assertFalse(h.summarize_transaction(target)["complete"])
            self.assertEqual(h.analyze_history(target, [transaction("prior", 180)])["status"], "unavailable")

    def test_old_window_duplicates_and_record_cap(self):
        target = transaction("target", 100000)
        old = transaction("old", 1)
        recent = transaction("recent", 99990)
        report = h.analyze_history(target, [old, recent, recent])
        self.assertEqual(report["coverage"]["excluded"]["outside_window"], 1)
        self.assertEqual(report["coverage"]["excluded"]["duplicate"], 1)
        self.assertFalse(report["findings"])
        report = h.analyze_history(target, (recent for _ in range(1000)))
        self.assertEqual(report["coverage"]["inspected_transactions"], 100)
        self.assertTrue(report["coverage"]["input_truncated"])
        self.assertFalse(report["coverage"]["complete_history"])

    def test_missing_child_or_orphan_authority_does_not_supply_history(self):
        partial = transaction("partial", 100)
        partial["receipts"][0]["execution_outcome"]["outcome"]["receipt_ids"] = ["missing"]
        orphan = transaction("orphan", 110)
        extra = transaction("extra", 111)["receipts"][0]
        orphan["receipts"].append(extra)
        report = h.analyze_history(transaction("target", 200), [partial, orphan])
        self.assertFalse(report["related_transactions"])
        self.assertEqual(report["coverage"]["excluded"]["incomplete"], 2)


class IdentityTest(unittest.TestCase):
    def test_staging_and_mainnet_contract_histories_are_not_joined(self):
        target = transaction("target", 200)
        prior = transaction("prior", 100, receiver="staging-intents.near")
        report = h.analyze_history(target, [prior])
        self.assertFalse(report["related_transactions"])
        self.assertEqual(report["coverage"]["excluded"]["unrelated"], 1)

    def test_real_relayer_events_identify_user_not_relayer_or_transfer_recipient(self):
        summary = h.summarize_transaction(fixture("normal_relayer_signed_by_intents"))
        self.assertEqual(summary["participants"], ["81c9982bdae84b3f8553c7b40f0a3b663405f9427307056422ebe6cfcc9ad36b"])
        self.assertNotIn("intents.near", summary["actors"])
        self.assertNotIn("orderbook.fi.tg", summary["participants"])

    def test_unsigned_payload_reverted_events_and_wrong_emitters_do_not_identify_user(self):
        log = event("mt_mint", owner_id="victim.near", token_ids=["nep141:wrap.near"], amounts=["100"])
        failed = transaction("failed", 100, actor="unknown-relayer.near", method="execute_intents", logs=[log])
        forged = transaction("forged", 110, actor="unknown-relayer.near", receiver="evil.near", method="execute_intents", failure=False, logs=[log])
        for tx in (failed, forged):
            payload = {"signed": [{"payload": json.dumps({"signer_id": "victim.near"})}]}
            tx["transaction"]["actions"][0]["FunctionCall"]["args"] = base64.b64encode(json.dumps(payload).encode()).decode()
            self.assertFalse(h.summarize_transaction(tx)["participants"])

    def test_large_valid_amounts_identify_withdrawal_but_invalid_amounts_do_not(self):
        for amount in (str(10**24), str(2**128 - 1)):
            tx = transaction("withdraw", 100, method="execute_intents", failure=False,
                logs=[event("mt_burn", owner_id="alice.near", token_ids=["nep141:wrap.near"], amounts=[amount], memo="withdraw")])
            self.assertEqual(h.summarize_transaction(tx)["withdrawal_actors"], ["alice.near"])
        for amount in (str(2**128), "-1", "1e24", True, "", "１２"):
            tx = transaction("withdraw", 100, method="execute_intents", failure=False,
                logs=[event("mt_burn", owner_id="alice.near", token_ids=["nep141:wrap.near"], amounts=[amount], memo="withdraw")])
            self.assertFalse(h.summarize_transaction(tx)["withdrawal_actors"])

    def test_real_normal_deposit_then_withdraw_is_context_without_an_alert(self):
        report = h.analyze_history(fixture("normal_withdrawal_ft_withdraw"), [fixture("normal_deposit_ft_transfer_call")])
        self.assertEqual(report["status"], "available")
        self.assertEqual(len(report["related_transactions"]), 1)
        self.assertFalse(report["findings"])


class FindingsTest(unittest.TestCase):
    def test_repeated_probes_require_same_direct_actor_and_current_probe(self):
        prior = [transaction("p1", 100), transaction("p2", 110, method="acl_grant_role")]
        target = transaction("target", 120, method="state_migrate")
        report = h.analyze_history(target, prior)
        self.assertEqual([(f["rule"], f["severity"]) for f in report["findings"]], [("history_repeated_failed_private_probes", "medium")])
        self.assertEqual(report["findings"][0]["transaction_hashes"], ["p2", "p1"])
        self.assertFalse(h.analyze_history(transaction("other", 120, actor="bob.near"), prior)["findings"])
        ordinary = transaction("ordinary", 120, method="ft_withdraw", failure=False)
        self.assertFalse(h.analyze_history(ordinary, prior)["findings"])
        self.assertFalse(h.analyze_history(target, [prior[0], prior[0]])["findings"])

    def test_prior_credit_beneficiary_does_not_make_withdrawal_malicious(self):
        prior = transaction("deposit", 100, actor="donor.near", method="ft_on_transfer", failure=False,
            logs=[event("mt_mint", owner_id="victim.near", token_ids=["nep141:wrap.near"], amounts=["100"])])
        target = transaction("withdraw", 110, actor="victim.near", method="ft_withdraw", failure=False,
            logs=[event("mt_burn", owner_id="victim.near", token_ids=["nep141:wrap.near"], amounts=["10"], memo="withdraw")])
        accounting = {"findings": [{"rule": "accounting_credit_exceeds_backing", "severity": "high",
                                    "evidence": {"retained_credit_owners": ["victim.near"]}}]}
        with patch("near.intents.accounting.analyze_accounting", return_value=accounting):
            report = h.analyze_history(target, [prior])
        self.assertEqual([f["severity"] for f in report["findings"]], ["low"])
        self.assertIn("does not establish", report["findings"][0]["message"])

    def test_summaries_match_raw_features_and_never_contain_nonfinite_values(self):
        target, priors = transaction("target", 120), [transaction("p1", 100), transaction("p2", 110)]
        actual = h.history_features(target, priors)
        expected = h.history_features_from_summaries(h.summarize_transaction(target), map(h.summarize_transaction, priors))
        self.assertEqual(actual, expected)
        self.assertEqual(tuple(actual), h.HISTORY_FEATURE_KEYS)
        self.assertTrue(all(type(v) is float and math.isfinite(v) for v in actual.values()))
        self.assertEqual(actual["history_repeated_failed_probe"], 1)
        self.assertEqual(h.history_features(target, [])["history_available"], 0)


if __name__ == "__main__":
    unittest.main()
