import unittest

from near.intents.taxonomy import (FAMILIES, RULE_FAMILIES, TAXONOMY, categories_for_rules,
                                   classify_metadata, family_for_campaign)


class TaxonomyTest(unittest.TestCase):
    def test_main_protocol_types_are_distinct_from_attack_mechanisms(self):
        self.assertIn("lending", TAXONOMY["main_review"]["protocol_types"])
        self.assertNotIn("lending", FAMILIES)
        self.assertEqual(FAMILIES["async_reentrancy"]["observability"], "detectable_with_context")
        self.assertEqual(FAMILIES["bridge_validation"]["observability"], "not_observable")
        for family in FAMILIES.values():
            self.assertIn(family["observability"], TAXONOMY["observability"])
            self.assertTrue(set(family["sources"]) <= TAXONOMY["sources"].keys())
        self.assertTrue(set(RULE_FAMILIES.values()) <= FAMILIES.keys())

    def test_known_families_are_explicit_and_unknown_does_not_guess(self):
        self.assertEqual(family_for_campaign("oct_exploit / exploit"), "callback_accounting")
        self.assertEqual(family_for_campaign("sandbox:callback_low_gas"), "resource_exhaustion")
        self.assertEqual(family_for_campaign("async_reentrancy"), "async_reentrancy")
        self.assertEqual(family_for_campaign("rhea_margin_circular_swap_2026_04"), "accounting_logic")
        self.assertEqual(family_for_campaign("skyward_duplicate_redemption_2022_11"), "share_accounting")
        for name in ("reentrancy.near", "withdraw", "my_new_exploit", None):
            self.assertIsNone(family_for_campaign(name))

    def test_associated_and_unlabelled_traffic_are_not_positive_training_rows(self):
        for role in ("setup", "cashout", "setup_funding_via_intents"):
            result = classify_metadata({"campaign": "oct_exploit", "label": 1, "role": role})
            self.assertEqual(result["outcome"], "associated_activity")
            self.assertIsNone(result["supervised_label"])
        for meta in ({"role": "exploit"}, {"label": 1}, {"label": 0, "role": "exploit"},
                     {"source": "fastnear-fresh", "label": "unknown"}):
            self.assertIsNone(classify_metadata(meta)["supervised_label"])

    def test_real_verbose_campaign_labels_and_team_controls(self):
        campaigns = {
            "2026-10-01 NEAR Intents deposit-notify ghost balance exploit (USDT-BSC via HOT Omni)": "callback_accounting",
            "2026-04-03 notify callback out-of-gas attempts (CallbackOogReturn), refunds held": "resource_exhaustion",
            "2026-05-20..21 fake-token / token-id spoof fuzzing of intents.near": "token_spoofing",
            "2026-05-23..31 admin/private-method fuzzing of intents.near (test1779579480756.near)": "access_control",
        }
        for campaign, family in campaigns.items():
            self.assertEqual(classify_metadata({"campaign": campaign, "label": 1, "role": "attempt"})["category"], family)
        team = classify_metadata({"campaign": "2026-10-02 defuse-ops post-fix notify regression tests (team, not attacker)",
                                  "role": "team_regression_test", "label": 0})
        self.assertEqual(team["category"], "callback_accounting")
        self.assertEqual(team["supervised_label"], 0)
        self.assertEqual(team["outcome"], "benign")
        self.assertIsNone(family_for_campaign("2026-10-01 an unrelated incident"))

    def test_canonical_family_overrides_lower_level_scenario(self):
        result = classify_metadata({"family": "resource_exhaustion", "attack_family": "notify_receiver_failure",
                                    "source": "sandbox", "label": "attack", "role": "attempt"})
        self.assertEqual(result["category"], "resource_exhaustion")

    def test_attempts_stay_distinct_from_exploits_and_synthetic_stays_separate(self):
        attempt = classify_metadata({"source": "sandbox", "campaign": "sandbox:admin_probe",
                                     "label": "attack", "role": "attempt"})
        self.assertEqual(attempt, {"category": "access_control", "outcome": "attempt",
                                  "supervised_label": 1, "provenance": "sandbox"})
        generated = classify_metadata({"source": "generated_receipt", "attack_family": "callback_accounting",
                                       "label": "attack", "role": "exploit"})
        self.assertEqual(generated["provenance"], "generated")
        self.assertEqual(generated["outcome"], "exploit")

    def test_runtime_categories_do_not_guess_root_causes(self):
        hits = [{"rule": rule} for rule in ("accounting_credit_exceeds_backing", "log_limit", "credit_kept",
                                             "private_method_direct", "execute_intents_panic", "unknown_method")]
        categories = categories_for_rules(hits)
        self.assertEqual([c["id"] for c in categories], ["callback_accounting", "access_control", "resource_exhaustion"])
        self.assertEqual(categories[0]["rules"], ["accounting_credit_exceeds_backing", "credit_kept"])
        self.assertTrue(all("not a verified root cause" in c["evidence_basis"] for c in categories))
        self.assertEqual(categories_for_rules([{"rule": "execute_intents_panic"}]), [])


if __name__ == "__main__":
    unittest.main()
