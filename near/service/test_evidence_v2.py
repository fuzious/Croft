"""Evidence integration preserves baseline decisions and bounds optional history reads."""
import copy
import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from near.intents import history
from near.service import app, intents
from near.service.test_intents import EXPLOIT, NORMAL, HAS_MODEL, MODEL_SKIP, Replay, recorded_tx


def baseline(label="low"):
    return {"label": label, "risk": 0.1 if label == "low" else 1.0, "rule_hits": [],
            "flow": "deposit", "top_features": [], "anomaly_score": 0.1, "anomaly_percentile": 0.1}


def shifted(tx, hash_, height_delta=0, time_delta=0):
    result = copy.deepcopy(tx)
    result["transaction"]["hash"] = hash_
    result["execution_outcome"]["id"] = hash_
    outcomes = [result["execution_outcome"], *(r["execution_outcome"] for r in result["receipts"]),
                *result.get("data_receipts", [])]
    for outcome in outcomes:
        outcome["block_height"] += height_delta
        outcome["block_timestamp"] = str(int(outcome["block_timestamp"]) + time_delta)
    return result


class HistoryTransport:
    def __init__(self, target, priors=(), failure=None):
        self.target = target
        self.priors = list(priors)
        self.failure = failure
        self.calls = []

    def __call__(self, path, body):
        self.calls.append((path, body))
        if path == "/account":
            if self.failure:
                raise self.failure
            result = {"account_txs": [{"transaction_hash": tx["transaction"]["hash"]} for tx in self.priors]}
        else:
            by_hash = {tx["transaction"]["hash"]: tx for tx in [self.target, *self.priors]}
            result = {"transactions": [by_hash[h] for h in body["tx_hashes"]]}
        return 200, {}, json.dumps(result).encode()


class EvidenceIntegrationTest(unittest.TestCase):
    def test_api_rejects_unbound_outcomes_before_model_scoring(self):
        def missing_id(tx):
            del tx["receipts"][0]["execution_outcome"]["id"]

        def missing_executor(tx):
            del tx["receipts"][0]["execution_outcome"]["outcome"]["executor_id"]

        changes = (
            lambda tx: tx["execution_outcome"].update(id="different-transaction"),
            lambda tx: tx["receipts"][0]["execution_outcome"].update(id="different-receipt"),
            lambda tx: tx["receipts"][0]["execution_outcome"]["outcome"].update(executor_id="forged.near"),
            missing_id, missing_executor,
        )
        for change in changes:
            with self.subTest(change=change.__name__):
                tx = recorded_tx(EXPLOIT)
                change(tx)
                with patch.object(intents, "TRANSPORT", HistoryTransport(tx)), patch.object(intents, "score") as scorer, \
                        patch.object(intents, "model_info", return_value={}):
                    response = TestClient(app.app).post("/v1/transactions/score", json={"tx_hash": EXPLOIT})
                self.assertEqual(response.status_code, 502, response.text)
                scorer.assert_not_called()

    def test_accounting_promotes_a_supported_pattern_and_preserves_baseline(self):
        tx = recorded_tx(EXPLOIT)
        base = baseline()
        result = intents._enhanced(tx, base, intents._history_evidence(tx))
        self.assertEqual(result["label"], "high")
        self.assertEqual(result["risk"], 1.0)
        self.assertEqual(result["baseline"]["label"], "low")
        self.assertEqual(base, baseline())
        self.assertTrue(any(h["rule"] == "accounting_credit_exceeds_backing" for h in result["rule_hits"]))
        self.assertIn("callback_accounting", [c["id"] for c in result["attack_categories"]])
        self.assertEqual(result["history"]["status"], "not_requested")

    def test_history_is_contextual_and_never_downgrades_baseline(self):
        tx = recorded_tx(NORMAL)
        context = intents._history_evidence(tx, [])
        context.update(status="available", findings=[{"rule": "history_pattern", "severity": "high", "message": "test"}])
        result = intents._enhanced(tx, baseline(), context)
        self.assertEqual(result["label"], "medium")
        self.assertEqual(result["rule_hits"][0]["severity"], "medium")
        self.assertEqual(intents._enhanced(tx, baseline("high"), context)["label"], "high")
        context["status"] = "unavailable"
        self.assertEqual(intents._enhanced(tx, baseline(), context)["label"], "low")

    def test_default_score_still_uses_only_one_read(self):
        transport = HistoryTransport(recorded_tx(NORMAL))
        with patch.object(intents, "score", return_value=baseline()):
            result = intents.score_hash(NORMAL, transport=transport)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(result["history"]["status"], "not_requested")
        self.assertEqual(result["accounting"]["status"], "checked")
        self.assertEqual(result["baseline"]["label"], "low")

    def test_optional_history_timeout_preserves_transaction_and_reports_unknown(self):
        transport = HistoryTransport(recorded_tx(NORMAL), failure=TimeoutError("history timed out"))
        with patch.object(intents, "score", return_value=baseline()):
            result = intents.score_hash(NORMAL, transport=transport, include_history=True)
        self.assertEqual(result["label"], "low")
        self.assertEqual(result["history"]["status"], "unavailable")
        self.assertIn("could not be read", result["history"]["reason"])
        self.assertEqual(len(transport.calls), 2)
        self.assertFalse(result["history"]["coverage"]["complete_history"])

    def test_history_excludes_future_even_if_index_ignores_query_bound(self):
        target = recorded_tx(NORMAL)
        future = shifted(target, EXPLOIT, height_delta=100, time_delta=100 * 10**9)
        transport = HistoryTransport(target, [future])
        with patch.object(intents, "score", return_value=baseline()):
            result = intents.score_hash(NORMAL, transport=transport, include_history=True)
        self.assertEqual(result["history"]["status"], "no_prior_evidence")
        self.assertEqual(result["history"]["coverage"]["excluded"]["not_strictly_earlier"], 1)
        query = transport.calls[1][1]
        self.assertEqual(query["to_tx_block_height"], target["execution_outcome"]["block_height"] - 1)
        self.assertEqual(query["limit"], 20)

    def test_history_cannot_link_deposits_through_a_shared_relayer(self):
        target = recorded_tx(NORMAL)
        prior = shifted(recorded_tx(EXPLOIT), EXPLOIT,
                        height_delta=target["execution_outcome"]["block_height"] - recorded_tx(EXPLOIT)["execution_outcome"]["block_height"] - 100,
                        time_delta=int(target["execution_outcome"]["block_timestamp"]) - int(recorded_tx(EXPLOIT)["execution_outcome"]["block_timestamp"]) - 100 * 10**9)
        target["transaction"]["signer_id"] = "meteor-relayer.near"
        prior["transaction"]["signer_id"] = "meteor-relayer.near"
        transport = HistoryTransport(target, [prior])
        with patch.object(intents, "score", return_value=baseline()):
            result = intents.score_hash(NORMAL, transport=transport, include_history=True)
        self.assertEqual(result["label"], "low")
        self.assertEqual(result["history"]["related_transactions"], [])
        self.assertNotIn("meteor-relayer.near", result["history"]["target_participants"])

    def test_two_account_and_four_additional_request_limit(self):
        target = recorded_tx(NORMAL)
        prior = shifted(target, EXPLOIT, height_delta=-100, time_delta=-100 * 10**9)
        transport = HistoryTransport(target, [prior])
        real_analyze = history.analyze_history

        def many_participants(tx, priors):
            out = real_analyze(tx, priors)
            out["target_participants"] = ["a.near", "b.near", "c.near", "bad/path", "intents.near"]
            return out

        with patch.object(intents, "score", return_value=baseline()), patch.object(history, "analyze_history", side_effect=many_participants):
            result = intents.score_hash(NORMAL, transport=transport, include_history=True)
        self.assertEqual(len(transport.calls), 5)
        self.assertEqual(result["history"]["coverage"]["requests"], 4)
        self.assertEqual(result["history"]["coverage"]["queried_accounts"], ["a.near", "b.near"])

    def test_api_passes_optional_history_and_returns_separate_layer_metadata(self):
        transport = HistoryTransport(recorded_tx(NORMAL))
        with patch.object(intents, "TRANSPORT", transport), patch.object(intents, "score", return_value=baseline()), \
                patch.object(intents, "model_info", return_value={"version": "fixture"}):
            response = TestClient(app.app).post("/v1/transactions/score", json={"tx_hash": NORMAL, "include_history": True})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["model"]["version"], "fixture")
        self.assertEqual(body["detector"]["version"], "transaction-evidence-v2")
        self.assertTrue(body["history"]["coverage"]["requested"])
        self.assertEqual(len(transport.calls), 2)

    @unittest.skipUnless(HAS_MODEL, MODEL_SKIP)
    def test_recorded_scan_adds_history_without_extra_network_requests(self):
        from near.service.test_intents import EXPLOITER
        intents.clear_cache()
        self.addCleanup(intents.clear_cache)
        replay = Replay()
        result = intents.recent_activity(EXPLOITER, transport=replay)
        self.assertEqual(result["requests"], len(replay.calls))
        self.assertLessEqual(len(replay.calls), 3)
        self.assertTrue(all(t["history"]["coverage"]["requests"] == 0 for t in result["txs"]))
        self.assertTrue(all("accounting" in t and "baseline" in t for t in result["txs"]))


if __name__ == "__main__":
    unittest.main()
