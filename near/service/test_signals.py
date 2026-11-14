import unittest

from near.service import signals


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
