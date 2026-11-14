"""Tests for the NEAR Intents anomaly model: threshold logic, labels, the per-flow tail model, freeze and reload with
hash checks, and the score_tx shape. Transactions are the real mainnet fixtures recorded by the features owner
(near/intents/fixtures/features/); no network and no mocks."""
import gzip
import json
import math
import shutil
import tempfile
import unittest
from pathlib import Path

import numpy as np

from near.intents import evaluate as ev
from near.intents import features as ft
from near.intents import model as md

FIX = Path(__file__).parent / "fixtures" / "features"
NORMALS = [
    "normal_deposit_ft_transfer_call", "normal_deposit_mt_deposit_call", "normal_execute_intents",
    "normal_execute_intents_failed", "normal_withdrawal_ft_withdraw", "normal_delegate",
    "normal_relayer_signed_by_intents",
]


def load(name: str) -> dict:
    with gzip.open(FIX / f"{name}.json.gz", "rt") as f:
        return json.load(f)


class AlertThresholdTest(unittest.TestCase):
    def test_threshold_keeps_alerts_within_budget(self):
        s = np.arange(1.0, 1001.0)  # 1000 calibration scores, budget 1/100 = 10 alerts
        t = md.alert_threshold(s, np.zeros(1000, bool), 1 / 100)
        self.assertEqual(int((s >= t).sum()), 10)
        self.assertGreater(t, 990.0)
        self.assertLessEqual(t, 991.0)

    def test_zero_budget_puts_threshold_above_every_score(self):
        s = np.arange(1.0, 101.0)
        t = md.alert_threshold(s, np.zeros(100, bool), 1 / 10_000)
        self.assertEqual(int((s >= t).sum()), 0)
        self.assertTrue(math.isfinite(t))

    def test_forced_alerts_use_the_budget_first(self):
        s = np.arange(1.0, 1001.0)
        forced = np.zeros(1000, bool)
        forced[:4] = True  # four rule alerts on low-scoring rows
        t = md.alert_threshold(s, forced, 1 / 100)
        self.assertEqual(int((forced | (s >= t)).sum()), 10)

    def test_forced_alerts_over_budget_disable_the_anomaly_threshold(self):
        s = np.arange(1.0, 101.0)
        forced = np.zeros(100, bool)
        forced[:3] = True
        self.assertEqual(md.alert_threshold(s, forced, 1 / 100), math.inf)

    def test_ties_at_the_cut_are_not_split(self):
        s = np.array([5.0, 5.0, 5.0, 1.0] + [0.0] * 96)
        t = md.alert_threshold(s, np.zeros(100, bool), 2 / 100)
        self.assertEqual(int((s >= t).sum()), 0)


class LabelTest(unittest.TestCase):
    THR = {"high": 10.0, "medium": 5.0}

    def test_rule_severity_and_score_combine_by_max(self):
        self.assertEqual(md.label_for("high", 0.0, self.THR), "high")
        self.assertEqual(md.label_for("medium", 0.0, self.THR), "medium")
        self.assertEqual(md.label_for("medium", 11.0, self.THR), "high")
        self.assertEqual(md.label_for("low", 6.0, self.THR), "medium")
        self.assertEqual(md.label_for("low", 4.9, self.THR), "low")
        self.assertEqual(md.label_for(None, 10.0, self.THR), "high")

    def test_max_severity(self):
        self.assertEqual(md.max_severity([]), None)
        self.assertEqual(md.max_severity(["low", "high", "medium"]), "high")


class TailModelTest(unittest.TestCase):
    def setUp(self):
        rng = np.random.default_rng(0)
        self.X = rng.normal(size=(2000, 3)).astype(np.float32)
        self.flows = np.array(["deposit"] * 1000 + ["execute_intents"] * 1000)
        self.m = md.TailModel(("a", "b", "c")).fit(self.X, self.flows)

    def test_unseen_extreme_value_scores_higher_than_typical_row(self):
        typical = self.m.score(np.zeros((1, 3), np.float32), np.array(["deposit"]))[0]
        extreme = self.m.score(np.array([[0.0, 50.0, 0.0]], np.float32), np.array(["deposit"]))[0]
        self.assertLess(typical, 1.0)
        self.assertGreater(extreme, 2.5)  # -log10(2 / 1001) for a value outside all 1000 rows

    def test_explain_names_the_unusual_feature_first(self):
        top = self.m.explain(np.array([0.0, 50.0, 0.0], np.float32), "deposit", k=2)
        self.assertEqual(top[0]["feature"], "b")
        self.assertEqual(set(top[0]), {"feature", "value", "tail_p", "typical"})

    def test_unknown_flow_falls_back_to_all_training_rows(self):
        s = self.m.score(np.zeros((1, 3), np.float32), np.array(["never_seen"]))[0]
        self.assertLess(s, 1.0)


def tiny_artifact() -> dict:
    """An artifact fitted on the seven recorded real normal fixtures (too few for real use, enough for shape)."""
    txs = [load(n) for n in NORMALS]
    X = np.array([[ft.tx_features(t)[k] for k in ft.FEATURE_KEYS] for t in txs], np.float32)
    flows = np.array([ft.flow_type(t) for t in txs])
    tail = md.TailModel(ft.FEATURE_KEYS).fit(X, flows)
    scores = tail.score(X, flows)
    return md.build_artifact("tail_per_flow", tail, tail, scores,
                             {"high": float(scores.max()) + 1, "medium": float(scores.max()) + 0.5},
                             train_ids=[t["transaction"]["hash"] for t in txs])


class FreezeReloadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "root"
        for f in md.CODE_FILES:
            (self.root / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(md.ROOT / f, self.root / f)
        self.pkl = md.save_artifact(tiny_artifact(), self.tmp / "out", "intents_test", root=self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_manifest_records_hashes_and_reload_round_trips(self):
        man = json.loads(self.pkl.with_suffix(".json").read_text())
        self.assertEqual(set(man["code_sha256"]), set(md.CODE_FILES))
        self.assertEqual(len(man["train_ids_sha256"]), 64)
        self.assertEqual(man["pkl_sha256"], md.sha256_file(self.pkl))
        art = md.load_artifact(self.pkl, root=self.root)
        self.assertEqual(art["kind"], "tail_per_flow")
        self.assertEqual(art["feature_keys"], list(ft.FEATURE_KEYS))

    def test_reload_refuses_changed_feature_code(self):
        with open(self.root / "near/intents/features.py", "a") as f:
            f.write("\n# changed\n")
        with self.assertRaisesRegex(ValueError, "features.py"):
            md.load_artifact(self.pkl, root=self.root)

    def test_reload_refuses_changed_pickle(self):
        with open(self.pkl, "ab") as f:
            f.write(b"\0")
        with self.assertRaisesRegex(ValueError, "pkl"):
            md.load_artifact(self.pkl, root=self.root)


class ScoreTxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.art = tiny_artifact()

    def test_exploit_scores_high_with_rule_reasons(self):
        r = md.score_tx(load("exploit_2GQ2zQ"), self.art)
        self.assertEqual(set(r), {"risk", "label", "rule_hits", "top_features", "anomaly_score",
                                  "anomaly_percentile", "flow"})
        self.assertEqual(r["label"], "high")
        self.assertEqual(r["risk"], 1.0)
        self.assertIn("failed_resolve_callback", {h["rule"] for h in r["rule_hits"]})
        self.assertEqual(r["flow"], "deposit")
        self.assertTrue(r["top_features"])

    def test_normal_fixture_has_bounded_risk_and_json_safe_output(self):
        r = md.score_tx(load("normal_execute_intents"), self.art)
        self.assertGreaterEqual(r["risk"], 0.0)
        self.assertLessEqual(r["risk"], 1.0)
        self.assertIn(r["label"], ("low", "medium", "high"))
        json.dumps(r)

    def test_rpc_shape_gives_the_same_score_as_fastnear_shape(self):
        a = md.score_tx(load("exploit_2GQ2zQ"), self.art)
        b = md.score_tx(load("exploit_2GQ2zQ_rpc"), self.art)
        self.assertEqual((a["label"], a["risk"], a["anomaly_score"]), (b["label"], b["risk"], b["anomaly_score"]))


class EvaluateHelpersTest(unittest.TestCase):
    def test_campaign_keys_use_short_names(self):
        self.assertEqual(ev.campaign_key("2026-10-01 NEAR Intents deposit-notify ghost balance exploit", "exploit"),
                         "oct_exploit / exploit")
        self.assertEqual(
            ev.campaign_key("2026-10-02 defuse-ops post-fix notify regression tests", "team_regression_test"),
            "team_regression / team_regression_test")

    def test_ablation_systems_differ_only_in_what_they_use(self):
        art = {"thresholds": {"high": 0.9, "medium": 0.5}, "thresholds_anomaly_only": {"high": 0.8, "medium": 0.4}}
        sev = np.array([3, 2, 0, 0, 1], np.int8)
        s = np.array([0.0, 0.0, 0.85, 0.45, 0.1])
        labs = ev.system_labels(art, s, sev)
        self.assertEqual(labs["rules_only"].tolist(), ["high", "medium", "low", "low", "low"])
        self.assertEqual(labs["anomaly_only"].tolist(), ["low", "low", "high", "medium", "low"])
        self.assertEqual(labs["combined"].tolist(), ["high", "medium", "medium", "low", "low"])

    def test_level_counts_and_wilson(self):
        c = ev.level_counts(np.array(["high", "medium", "low", "low"], dtype=object))
        self.assertEqual((c["high"], c["medium"], c["missed"]), (1, 1, 2))
        lo, hi = c["medium_plus_rate"]["ci95"]
        self.assertAlmostEqual(lo, 0.150, places=3)
        self.assertAlmostEqual(hi, 0.850, places=3)
        self.assertEqual(ev.wilson(0, 7735)[0], 0.0)
        self.assertAlmostEqual(ev.wilson(0, 7735)[1], 0.000496, places=6)

    def test_tables_header_carries_the_caveats_from_results(self):
        md_text = ev.tables(json.loads(ev.EVAL_JSON.read_text()))
        header = md_text.split("\n## ", 1)[0]
        self.assertIn("pool the 2026-10-01 paused hour", header)
        self.assertIn("RESULTS.md 'Alerts per day'", header)
        self.assertIn("rules were developed on these campaigns and on the scouting seeds", header)
        self.assertIn("RESULTS.md Limits 1 and 4", header)


if __name__ == "__main__":
    unittest.main()
