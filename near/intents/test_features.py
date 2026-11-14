"""Feature and rule tests on real transactions recorded from mainnet.

Fixtures under fixtures/features/ are real transactions copied from the scouting downloads on 2026-11-14:
- FastNEAR /v0/transactions shape: the two 2026-10-01 exploit deposits (exploit_*) and October normals (normal_*);
- NEAR RPC EXPERIMENTAL_tx_status shape: exploit_2GQ2zQ_rpc (the same exploit tx), April out-of-gas callback attempts (april_*), May admin and spoof probes
  (may_*) and one post-fix team regression test (team_regression_refund)."""
import gzip
import json
import math
import time
import unittest
from pathlib import Path

from near.intents import features as ft

FIX = Path(__file__).parent / "fixtures" / "features"


def load(name: str) -> dict:
    with gzip.open(FIX / f"{name}.json.gz", "rt") as f:
        return json.load(f)


EXPLOITS = ["exploit_2GQ2zQ", "exploit_3k91uD"]
NORMALS = [
    "normal_deposit_ft_transfer_call",
    "normal_deposit_mt_deposit_call",
    "normal_execute_intents",
    "normal_execute_intents_failed",
    "normal_withdrawal_ft_withdraw",
    "normal_delegate",
    "normal_relayer_signed_by_intents",
]


def rules(tx: dict) -> dict[str, str]:
    return {h["rule"]: h["severity"] for h in ft.rule_hits(tx)}


class FlowTypeTest(unittest.TestCase):
    def test_flow_types_of_real_transactions(self):
        expected = {
            "exploit_2GQ2zQ": "deposit",
            "normal_deposit_ft_transfer_call": "deposit",
            "normal_deposit_mt_deposit_call": "deposit",
            "normal_execute_intents": "execute_intents",
            "normal_execute_intents_failed": "execute_intents",
            "normal_withdrawal_ft_withdraw": "withdrawal",
            "april_oog_self_callback": "deposit",
            "may_admin_upgrade": "other",
        }
        for name, flow in expected.items():
            with self.subTest(name=name):
                self.assertEqual(ft.flow_type(load(name)), flow)


class FeatureVectorTest(unittest.TestCase):
    def test_every_fixture_yields_exactly_the_fixed_keys_as_finite_floats(self):
        for path in sorted(FIX.glob("*.json.gz")):
            name = path.name.removesuffix(".json.gz")
            with self.subTest(name=name):
                f = ft.tx_features(load(name))
                self.assertEqual(list(f), list(ft.FEATURE_KEYS))
                for k, v in f.items():
                    self.assertIsInstance(v, float, k)
                    self.assertTrue(math.isfinite(v), k)

    def test_flow_one_hot_matches_flow_type(self):
        for name in EXPLOITS + NORMALS:
            with self.subTest(name=name):
                tx = load(name)
                f = ft.tx_features(tx)
                hot = [k for k in ("flow_deposit", "flow_execute_intents", "flow_withdrawal", "flow_other") if f[k]]
                self.assertEqual(hot, [f"flow_{ft.flow_type(tx)}"])

    def test_features_ignore_account_names(self):
        """Renaming the accounts (sandbox vs mainnet) must not change the features. Names keep their length,
        because log and argument byte sizes legitimately depend on it (the exploit used 64-char accounts)."""
        tx = load("exploit_2GQ2zQ")
        raw = json.dumps(tx)
        signer = tx["transaction"]["signer_id"]
        renamed = raw.replace(signer, "a" * len(signer)).replace("v2_1.omni.hot.tg", "mt-token.sandbox")
        self.assertNotEqual(raw, renamed)
        self.assertEqual(ft.tx_features(tx), ft.tx_features(json.loads(renamed)))

    def test_exploit_features_show_the_mechanism(self):
        f = ft.tx_features(load("exploit_2GQ2zQ"))
        self.assertGreaterEqual(f["n_failed_resolve"], 1)
        self.assertGreater(f["max_log_ratio"], 0.6)
        self.assertGreaterEqual(f["fail_log_limit"], 1)
        self.assertGreaterEqual(f["n_notify_receivers"], 1)
        self.assertGreater(f["refund_over_deposit_log10"], 30)
        self.assertGreater(f["credit_excess_log2"], 0.9)
        self.assertGreater(f["max_token_ids_per_event_log"], math.log1p(50))

    def test_normal_deposit_has_balanced_credit(self):
        f = ft.tx_features(load("normal_deposit_ft_transfer_call"))
        self.assertEqual(f["credit_excess_log2"], 0.0)
        self.assertEqual(f["n_failed"], 0.0)
        self.assertEqual(f["n_notify_receivers"], 0.0)

    def test_same_transaction_in_rpc_and_fastnear_shape_gives_identical_features_and_rules(self):
        self.assertEqual(ft.tx_features(load("exploit_2GQ2zQ")), ft.tx_features(load("exploit_2GQ2zQ_rpc")))
        self.assertEqual(ft.rule_hits(load("exploit_2GQ2zQ")), ft.rule_hits(load("exploit_2GQ2zQ_rpc")))

    def test_rpc_and_fastnear_shapes_give_the_same_receipt_counts(self):
        """The April attempt in RPC shape: 9 receipts, 3 of them gas refunds from system, depth 3+."""
        f = ft.tx_features(load("april_oog_self_callback"))
        self.assertAlmostEqual(f["n_receipts_log"], math.log1p(9))
        self.assertAlmostEqual(f["n_refund_receipts_log"], math.log1p(3))
        self.assertGreaterEqual(f["max_depth"], 3)


class RuleTest(unittest.TestCase):
    def test_exploits_hit_the_high_rules(self):
        for name in EXPLOITS:
            with self.subTest(name=name):
                r = rules(load(name))
                self.assertEqual(r.get("failed_resolve_callback"), "high")
                self.assertEqual(r.get("log_limit"), "high")
                self.assertEqual(r.get("credit_kept"), "high")
                self.assertIn("refund_exceeds_deposit", r)
                self.assertIn("notify_receiver_in_deposit", r)
                self.assertIn("many_token_ids", r)

    def test_rule_hits_have_the_contract_shape(self):
        for h in ft.rule_hits(load("exploit_2GQ2zQ")):
            self.assertEqual(set(h), {"rule", "severity", "message"})
            self.assertIn(h["rule"], ft.RULES)
            self.assertIn(h["severity"], ("high", "medium", "low"))
            self.assertTrue(h["message"])

    def test_normal_transactions_hit_no_high_or_medium_rule(self):
        for name in NORMALS:
            with self.subTest(name=name):
                self.assertEqual({k: v for k, v in rules(load(name)).items() if v != "low"}, {})

    def test_intents_signing_its_own_relayed_call_is_not_a_direct_private_call(self):
        """intents.near signs with its relayer keys; its outgoing mt_on_transfer is a contract call, not a user's."""
        self.assertNotIn("private_method_direct", rules(load("normal_relayer_signed_by_intents")))

    def test_normal_failed_execute_intents_is_low_only(self):
        self.assertEqual(rules(load("normal_execute_intents_failed")), {"execute_intents_panic": "low"})

    def test_april_out_of_gas_attempts(self):
        r = rules(load("april_oog_self_callback"))
        self.assertIn("callback_oog", r)
        self.assertIn("notify_receiver_in_deposit", r)
        self.assertNotIn("credit_kept", r)  # intents burned the refund; the attempt failed
        self.assertIn("callback_oog", rules(load("april_oog_on_transfer")))

    def test_admin_probes_by_non_role_caller(self):
        for name in ("may_admin_upgrade", "may_admin_acl_grant_role"):
            with self.subTest(name=name):
                self.assertEqual(rules(load(name)).get("admin_method_non_role"), "medium")

    def test_direct_on_transfer_by_signer_is_a_private_method_call(self):
        self.assertIn("private_method_direct", rules(load("may_direct_mt_on_transfer")))

    def test_post_fix_regression_test_asks_too_much_refund_but_keeps_no_credit(self):
        r = rules(load("team_regression_refund"))
        self.assertIn("refund_exceeds_deposit", r)
        self.assertNotIn("credit_kept", r)
        self.assertNotIn("failed_resolve_callback", r)


class EventParsingTest(unittest.TestCase):
    def test_parses_event_versions_and_both_data_shapes(self):
        logs = [
            'EVENT_JSON:{"standard":"dip4","version":"0.3.0","event":"token_diff","data":[{"intent_hash":"x"}]}',
            'EVENT_JSON:{"standard":"dip4","version":"0.4.3","event":"transfer","data":{"intent_hash":"y"}}',
            'EVENT_JSON:{"standard":"nep245","version":"1.0.0","event":"mt_mint","data":[{"owner_id":"a",'
            '"token_ids":["nep141:t"],"amounts":["5"]}]}',
            "EVENT_JSON:{not json",
            "Transfer 5 from a to b",
        ]
        evs = ft.parse_events(logs)
        self.assertEqual([(e["standard"], e["event"]) for e in evs[:3]],
                         [("dip4", "token_diff"), ("dip4", "transfer"), ("nep245", "mt_mint")])
        self.assertEqual(evs[1]["data"], [{"intent_hash": "y"}])
        self.assertEqual(evs[3]["standard"], "unparsed")
        self.assertEqual(len(evs), 4)


class SpeedTest(unittest.TestCase):
    def test_features_and_rules_run_over_2000_txs_per_second(self):
        txs = [load(n) for n in NORMALS] * 50
        t0 = time.perf_counter()
        for tx in txs:
            ft.tx_features(tx)
            ft.rule_hits(tx)
        rate = len(txs) / (time.perf_counter() - t0)
        self.assertGreater(rate, 2000)


if __name__ == "__main__":
    unittest.main()
