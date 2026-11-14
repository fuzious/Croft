import unittest
from unittest.mock import Mock, patch

from near.service import signals


class UpstreamValidationTest(unittest.TestCase):
    def setUp(self):
        self.cfg = signals.load_config({"NEAR_RPC_URL": "http://rpc", "ORACLE_CONTRACT_ID": "oracle.near"})
        signals._nb_cache.clear()

    def test_missing_rpc_code_hash_is_unknown_not_an_eoa(self):
        with patch.object(signals, "rpc", return_value={"amount": "10"}):
            with self.assertRaisesRegex(signals.SignalError, "no code hash"):
                signals.view_account(self.cfg, "x.near")

    def test_malformed_rpc_responses_become_signal_errors(self):
        for body in ([], None, {}, {"result": None}, {"error": "bad"}):
            with self.subTest(body=body), patch.object(signals.httpx, "post", return_value=Mock(status_code=200, json=lambda: body)):
                with self.assertRaises(signals.SignalError):
                    signals.rpc(self.cfg, "query", {})

    def test_malformed_onchain_results_are_unavailable(self):
        for value in (False, [], "allow", {"verdict": "allow"},
                      {"verdict": "allow", "score_bps": 0, "expires_at_ns": "oops", "code_hash": "hash"}):
            with self.subTest(value=value), patch.object(signals, "call_view", return_value=(value, None)):
                out = signals.onchain_oracle_signals(self.cfg, "x.near")
                self.assertFalse(out["onchain_verdict"]["available"])
        with patch.object(signals, "call_view", return_value=("false", None)):
            self.assertFalse(signals.onchain_oracle_signals(self.cfg, "x.near")["onchain_blocked"]["available"])

    def test_invalid_indexer_fields_do_not_crash_or_count_as_prior_interactions(self):
        with patch.object(signals, "nearblocks", return_value={"data": {"first_day": "not-a-date"}}):
            out = signals.history_signals(self.cfg, "x.near", True, "agent.near", 1_800_000_000 * 10**9)
        for key in ("age_days", "code_changed_days", "prior_interactions"):
            self.assertFalse(out[key]["available"], out[key])

    def test_zero_retry_after_cannot_loop_forever(self):
        with patch.object(signals.httpx, "get", return_value=Mock(status_code=429, headers={"retry-after": "0"})), \
                patch.object(signals.time, "sleep") as sleep:
            with self.assertRaisesRegex(signals.SignalError, "rate limit"):
                signals.nearblocks(self.cfg, "/stats")
        self.assertEqual(sleep.call_count, 3)


class ConfigTest(unittest.TestCase):
    def test_mainnet_defaults(self):
        c = signals.load_config({})
        self.assertEqual(c["network"], "mainnet")
        self.assertEqual(c["rpc_urls"][0], "https://rpc.mainnet.fastnear.com")
        self.assertEqual(c["nearblocks_api"], "https://api.nearblocks.io")
        self.assertIsNone(c["oracle_contract_id"])

    def test_overrides(self):
        c = signals.load_config({"NEAR_NETWORK": "testnet", "NEAR_RPC_URL": "http://my-rpc",
                                 "ORACLE_CONTRACT_ID": "oracle.testnet", "NEARBLOCKS_API_KEY": "k"})
        self.assertEqual((c["rpc_urls"], c["oracle_contract_id"], c["nearblocks_api_key"]),
                         (["http://my-rpc"], "oracle.testnet", "k"))
        self.assertEqual(c["nearblocks_api"], "https://api-testnet.nearblocks.io")

    def test_sandbox_has_no_indexer_and_history_is_unavailable(self):
        c = signals.load_config({"NEAR_NETWORK": "sandbox"})
        self.assertIsNone(c["nearblocks_api"])
        h = signals.history_signals(c, "alice.test.near", True, "agent.test.near", now_ns=0)
        self.assertTrue(all(not s["available"] for k, s in h.items()), h)
        self.assertIn("no NearBlocks indexer", h["age_days"]["error"])

    def test_eoa_has_no_code_change_signal(self):
        h = signals.history_signals(signals.load_config({"NEAR_NETWORK": "sandbox"}), "a.near", False, None, 0)
        self.assertTrue(h["code_changed_days"]["available"])
        self.assertIsNone(h["code_changed_days"]["value"])

    def test_unknown_network_rejected(self):
        with self.assertRaises(ValueError):
            signals.load_config({"NEAR_NETWORK": "betanet"})

    def test_oracle_contract_not_configured(self):
        o = signals.onchain_oracle_signals(signals.load_config({}), "a.near")
        self.assertEqual(o["onchain_blocked"]["error"], "not configured")


if __name__ == "__main__":
    unittest.main()
