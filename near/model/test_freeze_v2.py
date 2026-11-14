import os
import importlib.util
import pickle
import tempfile
import unittest
from pathlib import Path

import numpy as np
from scipy.stats import rankdata

from near.model import freeze, freeze_v2, predict
from near.model import train_classic_v2 as tc2
from near.model.test_predict import SRC, nontrivial_rows

PARAMS = dict(tc2.V1_PARAMS, iters=30, leaves=7, top_tokens=20)
HAS_V2_LLM = ((predict.MODELS_DIR / "llm_final" / "model.safetensors").exists()
              and all(importlib.util.find_spec(m) for m in ("torch", "transformers")))


def tiny_v2_artifact(rows):
    """A real (tiny) classical v2 model on the fixture rows; the LLM part is never run by these tests."""
    fns = [dict(r) for r in rows]
    M = tc2.matrices_for_source(predict.pseudo_files(fns), fns)
    y = np.array([r["label"] for r in rows])
    est = tc2.fit_model(PARAMS, tc2.BLOCKS["v2_noera"], M, y, tc2.weights(rows, PARAMS))
    s = tc2.predict_model(est, M)
    art = {"kind": "ensemble_v2", "version": "test_v2", "llm_dir": "unused", "llm_thresholds": {"block": 0.9, "warn": 0.5},
           "classical": {"estimator": est, "class_head": freeze_v2.fit_class_head_v2(rows, M, est), "params": PARAMS,
                         "thresholds": {"block": 0.9, "warn": 0.5}},
           "ref_classical": np.sort(s), "ref_llm": np.linspace(0, 1, 11), "thresholds": {"block": 0.9, "warn": 0.6}}
    return art, fns, M


class ModelSelectionTest(unittest.TestCase):
    def test_default_is_v2_when_its_llm_is_unpacked_and_env_selects_v1(self):
        self.assertEqual(predict.selected_model({}), "frozen_near_v2" if HAS_V2_LLM else "frozen_near_v1")
        self.assertEqual(predict.selected_model({"NEAR_ORACLE_MODEL": "frozen_near_v1"}), "frozen_near_v1")
        with self.assertRaises(predict.FrozenModelError):
            predict.selected_model({"NEAR_ORACLE_MODEL": "frozen_near_v9"})

    def test_v2_code_files_add_context_and_llm_code(self):
        v1, v2 = set(predict.code_files("v1")), set(predict.code_files("v2"))
        self.assertIn("near/model/train_classic.py", v1 - v2)
        self.assertTrue({"near/model/context.py", "near/model/train_classic_v2.py",
                         "near/model/llm_classifier.py", "near/model/encoder.py"} <= v2)


class EnsembleMathTest(unittest.TestCase):
    def test_percentile_is_mid_rank(self):
        ref = np.sort(np.array([0.1, 0.2, 0.2, 0.5]))
        self.assertTrue(np.allclose(predict.percentile(ref, np.array([0.0, 0.2, 0.5, 0.9])),
                                    [0.0, 0.5, 0.875, 1.0]))
        x = np.random.RandomState(0).rand(50)
        self.assertTrue(np.allclose(predict.percentile(np.sort(x), x), (rankdata(x) - 0.5) / len(x)))

    def test_ensemble_risk_is_monotone_in_each_component(self):
        art = {"ref_classical": np.linspace(0, 1, 101), "ref_llm": np.linspace(0, 1, 101)}
        lo = predict.ensemble_risk(art, np.array([0.2]), np.array([0.3]))
        self.assertLess(lo[0], predict.ensemble_risk(art, np.array([0.4]), np.array([0.3]))[0])
        self.assertLess(lo[0], predict.ensemble_risk(art, np.array([0.2]), np.array([0.6]))[0])


class DecisionRuleTest(unittest.TestCase):
    def summary(self, share=0.04, pair_lo=0.4):
        x = {"nested": {"block": {"clean_file_alarm_share": {"rate": share}}},
             "pooled": {"block": {"clean_file_alarm_share": {"rate": share}}},
             "pair_rank_real_vuln_not_shorter": {"k": 30, "n": 52, "rate": 0.58, "lo": pair_lo, "hi": 0.7}}
        return x

    def diffs(self, lo, pair_lo=-0.1):
        return {"block_confirmed_pooled": {"diff": 0.02, "lo": lo, "hi": 0.05},
                "pair_rank_not_shorter": {"diff": 0.05, "lo": pair_lo, "hi": 0.2}}

    def test_classical_kept_without_significant_gain(self):
        choice, why = freeze_v2.choose({"classical_v2": self.summary(), "llm_v2": self.summary()},
                                       {"llm_v2": self.diffs(-0.01)})
        self.assertEqual(choice, "classical_v2")
        self.assertIn("(3)", why[-1])

    def test_primary_gain_wins(self):
        choice, _ = freeze_v2.choose({"classical_v2": self.summary(), "llm_v2": self.summary()},
                                     {"llm_v2": self.diffs(0.005)})
        self.assertEqual(choice, "llm_v2")

    def test_ineligible_challenger_cannot_win(self):
        choice, _ = freeze_v2.choose({"classical_v2": self.summary(), "llm_v2": self.summary(share=0.08)},
                                     {"llm_v2": self.diffs(0.01)})
        self.assertEqual(choice, "classical_v2")

    def test_secondary_needs_pair_rank_above_chance_and_gain(self):
        s = {"classical_v2": self.summary(), "llm_v2": self.summary(pair_lo=0.52)}
        self.assertEqual(freeze_v2.choose(s, {"llm_v2": self.diffs(-0.01, pair_lo=0.01)})[0], "llm_v2")
        self.assertEqual(freeze_v2.choose(s, {"llm_v2": self.diffs(-0.01, pair_lo=-0.01)})[0], "classical_v2")


class PairsAndBootstrapTest(unittest.TestCase):
    def rows(self):
        return [{"id": "v1", "label": 1, "source": "audit", "group": "a", "pair_id": "f1", "code": "x" * 10},
                {"id": "f1", "label": 0, "source": "audit", "group": "a", "pair_id": "v1", "code": "x" * 20},
                {"id": "v2", "label": 1, "source": "fix_commit", "group": "b", "pair_id": "f2", "code": "x" * 30},
                {"id": "f2", "label": 0, "source": "fix_commit", "group": "b", "pair_id": "v2", "code": "x" * 30},
                {"id": "m", "label": 1, "source": "mutation", "group": "b", "pair_id": "f2", "code": "x"}]

    def test_real_pairs_split_by_length(self):
        rows = self.rows()
        self.assertEqual([len(a) for a in freeze_v2.real_pairs(rows)], [2, 2])
        pi, pj = freeze_v2.real_pairs(rows, True)
        self.assertEqual((rows[pi[0]]["id"], rows[pj[0]]["id"]), ("v2", "f2"))
        pi, _ = freeze_v2.real_pairs(rows, False)
        self.assertEqual(rows[pi[0]]["id"], "v1")

    def test_boot_diff_of_identical_models_is_zero(self):
        rows = self.rows()
        members = np.array([0, 2])
        d = freeze_v2.boot_diff(rows, np.array([1.0, 0.0]), np.array([1.0, 0.0]), members, n_boot=50)
        self.assertEqual((d["diff"], d["lo"], d["hi"], d["n"]), (0.0, 0.0, 0.0, 2))
        d = freeze_v2.boot_diff(rows, np.array([0.0, 0.0]), np.array([1.0, 1.0]), members, n_boot=50)
        self.assertEqual((d["diff"], d["lo"], d["hi"]), (1.0, 1.0, 1.0))


class V2ArtifactTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = nontrivial_rows()
        cls.art, cls.fns, cls.M = tiny_v2_artifact(cls.rows)
        cls.dir = tempfile.TemporaryDirectory()
        cls.llm = Path(cls.dir.name) / "llm"
        cls.llm.mkdir()
        for f in predict.LLM_FILES:
            (cls.llm / f).write_text(f"stand-in {f}")
        cls.pkl = os.path.join(cls.dir.name, "test_v2.pkl")
        with open(cls.pkl, "wb") as fh:
            pickle.dump(cls.art, fh)
        cls.man = {"version": "test_v2", "code_kind": "v2", "pkl_sha256": predict.sha256_file(cls.pkl),
                   "code_sha256": predict.code_hashes("v2"), "llm_dir": str(cls.llm),
                   "llm_sha256": predict.llm_hashes(cls.llm), "thresholds": cls.art["thresholds"]}
        freeze.write_json(freeze.manifest_path(cls.pkl), cls.man)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_load_checks_the_llm_checkpoint(self):
        self.assertEqual(predict.load(self.pkl, cache=False)["info"]["version"], "test_v2")
        path = self.llm / "oracle.json"
        path.write_text("changed")
        try:
            with self.assertRaisesRegex(predict.FrozenModelError, "oracle.json"):
                predict.load(self.pkl, cache=False)
        finally:
            path.write_text("stand-in oracle.json")

    def test_load_refuses_changed_v2_code(self):
        man = dict(self.man, code_sha256=dict(self.man["code_sha256"], **{"near/model/context.py": "0" * 64}))
        freeze.write_json(freeze.manifest_path(self.pkl), man)
        try:
            with self.assertRaisesRegex(predict.FrozenModelError, "context.py"):
                predict.load(self.pkl, cache=False)
        finally:
            freeze.write_json(freeze.manifest_path(self.pkl), self.man)

    def test_classical_part_matches_training_featurization(self):
        out = predict.score_functions(self.fns, art=self.art, llm_scope=[False] * len(self.fns))
        want = tc2.predict_model(self.art["classical"]["estimator"], self.M)
        self.assertTrue(np.allclose([o["classical_risk"] for o in out], want, atol=1e-6))
        self.assertTrue(all(o["risk"] is None and o["llm_risk"] is None and not o["model_scored"] for o in out))
        self.assertTrue(all(o["vuln_class_guess"] for o in out))

    def test_trivial_functions_are_not_scored(self):
        fn = {"code": "pub fn version(&self) -> u64 {\n    self.version\n}", "fn": "version", "path": "src/lib.rs",
              "attrs": [], "is_public": True, "is_near_bindgen": True}
        out = predict.score_functions([fn], art=self.art, llm_scope=[False])[0]
        self.assertEqual((out["risk"], out["model_scored"]), (None, False))
        self.assertNotIn("classical_risk", out)


@unittest.skipUnless(HAS_V2_LLM, "v2 LLM checkpoint not unpacked (archives/near_llm_v2.zip)")
class FrozenV2Test(unittest.TestCase):
    """The frozen v2 model end to end (loads the merged LLM, a few seconds)."""

    def test_score_source_takes_max_over_counted_functions(self):
        res = predict.score_source({"src/lib.rs": SRC}, art=predict.load(predict.MODELS_DIR / "frozen_near_v2.pkl"))
        fns = {f["fn"]: f for f in res["functions"]}
        self.assertEqual(res["model"]["version"], "frozen_near_v2")
        counted = [f for f in res["functions"] if f["counts_toward_contract"]]
        self.assertEqual({f["fn"] for f in counted}, {"get_total", "set_owner"})
        self.assertTrue(all(f["llm_risk"] is not None and 0 <= f["risk"] <= 1 for f in counted))
        self.assertAlmostEqual(res["risk"], max(f["risk"] for f in counted))
        self.assertEqual(res["label"], predict.risk_label(res["risk"], res["thresholds"]))
        self.assertIsNone(fns["helper"]["risk"])  # not counted: classical score only, LLM not run
        self.assertIsNotNone(fns["helper"]["classical_risk"])

    def test_v1_stays_loadable(self):
        res = predict.score_source({"src/lib.rs": SRC}, art=predict.load(predict.FROZEN_V1))
        self.assertEqual(res["model"]["version"], "frozen_near_v1")


if __name__ == "__main__":
    unittest.main()
