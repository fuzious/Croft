import os
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from near.model import freeze, predict
from near.model import train_classic as tc
from near.model.test_train_classic import rows_fixture

PARAMS = {"lr": 0.1, "leaves": 7, "info": 0.3, "svd": 0, "top_tokens": 20, "iters": 30}

SRC = '''
#[near_bindgen]
impl Contract {
    pub fn get_total(&self) -> u64 {
        let t = self.total;
        t + 1
    }

    pub fn set_owner(&mut self, o: AccountId) {
        assert_eq!(env::signer_account_id(), self.owner);
        self.owner = o;
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    fn helper(&self) -> u64 {
        let x = 1;
        x + 1
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(1, 1);
    }
}
'''


def nontrivial_rows():
    """rows_fixture with multi-statement, multi-line bodies (trivial functions are not model-scored)."""
    rows = rows_fixture()
    for i, r in enumerate(rows):  # two classes so the vuln_class head can be fit
        r["vuln_class"] = ("signer_auth" if i % 2 else "missing_access_control") if r["label"] else None
        if r["label"]:
            r["code"] = (f"pub fn set_owner(&mut self, o: AccountId) {{\n    assert_eq!(env::signer_account_id(), "
                         f"self.owner);\n    self.owner{i % 5} = o;\n}}")
        else:
            r["code"] = f"pub fn get(&self) -> u64 {{\n    let v = self.v{i % 20};\n    v + 1\n}}"
    return rows


def tiny_artifact(rows):
    A, T, _ = tc.featurize_rows(rows, workers=0)
    return freeze.build_artifact(rows, A, T, PARAMS, {"block": 0.9, "warn": 0.5}, "test_v0"), A, T


class ArtifactTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = nontrivial_rows()
        cls.art, cls.A, cls.T = tiny_artifact(cls.rows)
        cls.dir = tempfile.TemporaryDirectory()
        cls.pkl = freeze.save_artifact(cls.art, cls.dir.name, "test_v0")

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_reload_checks_sha_and_returns_same_scores(self):
        art = predict.load(self.pkl)
        s = tc.predict_model(art["estimator"], self.A, self.T, None)
        self.assertTrue(np.allclose(s, tc.predict_model(self.art["estimator"], self.A, self.T, None)))
        with open(self.pkl, "ab") as f:
            f.write(b"x")
        try:
            with self.assertRaises(predict.FrozenModelError):
                predict.load(self.pkl, cache=False)
        finally:
            freeze.save_artifact(self.art, self.dir.name, "test_v0")

    def test_refuses_changed_feature_code(self):
        m = freeze.manifest_path(self.pkl)
        meta = freeze.read_json(m)
        meta["code_sha256"]["near/model/featurize.py"] = "0" * 64
        freeze.write_json(m, meta)
        try:
            with self.assertRaises(predict.FrozenModelError):
                predict.load(self.pkl, cache=False)
        finally:
            freeze.save_artifact(self.art, self.dir.name, "test_v0")

    def test_score_functions_matches_training_featurization(self):
        fns = [{k: r.get(k) for k in ("code", "fn", "impl", "attrs", "is_near_bindgen", "is_public", "trait",
                                      "is_payable", "path")} for r in self.rows]
        out = predict.score_functions(fns, art=self.art)
        want = tc.predict_model(self.art["estimator"], self.A, self.T, None)
        self.assertTrue(np.allclose([o["risk"] for o in out], want, atol=1e-6))
        self.assertTrue(all(o["vuln_class_guess"] for o in out))
        self.assertTrue(all("detector_hits" in o for o in out))

    def test_score_source_takes_max_over_public_contract_functions(self):
        res = predict.score_source({"src/lib.rs": SRC}, art=self.art)
        fns = {f["fn"]: f for f in res["functions"]}
        self.assertNotIn("it_works", fns)
        self.assertEqual(res["n_functions"], 4)
        self.assertFalse(fns["helper"]["counts_toward_contract"])
        self.assertEqual((fns["version"]["risk"], fns["version"]["model_scored"]), (None, False))
        self.assertFalse(fns["version"]["counts_toward_contract"])
        counted = [f["risk"] for f in res["functions"] if f["counts_toward_contract"]]
        self.assertAlmostEqual(res["risk"], max(counted))
        self.assertEqual(res["label"], predict.risk_label(res["risk"], self.art["thresholds"]))
        self.assertEqual(res["model"]["version"], "test_v0")
        self.assertEqual({t["fn"] for t in res["top"]}, {"get_total", "set_owner"})
        self.assertEqual([t["risk"] for t in res["top"]], sorted(counted, reverse=True))

    def test_source_without_contract_functions_is_low(self):
        res = predict.score_source({"probe.rs": "fn probe() {}"}, art=self.art)
        self.assertEqual((res["risk"], res["label"]), (0.0, "low"))


class RulesTest(unittest.TestCase):
    def test_risk_label(self):
        thr = {"block": 0.6, "warn": 0.3}
        self.assertEqual([predict.risk_label(x, thr) for x in (0.6, 0.59, 0.3, 0.29)],
                         ["high", "medium", "medium", "low"])

    def test_counts_toward_contract(self):
        base = {"is_public": True, "is_test": False, "path": "src/lib.rs", "code": "pub fn f() {}"}
        self.assertFalse(predict.counts_toward_contract(base | {"code": "pub fn f() -> u8 {\n    1\n}"}))
        base["code"] = "pub fn f(&mut self) {\n    let a = 1;\n    self.a = a;\n}"
        self.assertTrue(predict.counts_toward_contract(base))
        for change in ({"is_public": False}, {"is_test": True}, {"path": "tests/a.rs"}, {"path": "indexer/src/a.rs"},
                       {"code": "pub async fn f(&mut self) {\n    let a = 1;\n    self.a = a;\n}"}):
            self.assertFalse(predict.counts_toward_contract(base | change), change)


class SelectedModelTest(unittest.TestCase):
    def test_default_falls_back_to_v1_when_v2_llm_checkpoint_is_absent(self):
        with tempfile.TemporaryDirectory() as root:
            models = os.path.join(root, "near", "models")
            os.makedirs(models)
            with open(os.path.join(models, "frozen_near_v2.json"), "w") as f:
                f.write('{"llm_dir": "near/models/llm_final"}')
            self.assertEqual(predict.selected_model({}, root), "frozen_near_v1")
            os.makedirs(os.path.join(models, "llm_final"))
            open(os.path.join(models, "llm_final", "model.safetensors"), "w").close()
            with patch("near.model.predict.importlib.util.find_spec", return_value=object()):
                self.assertEqual(predict.selected_model({}, root), "frozen_near_v2")
            with patch("near.model.predict.importlib.util.find_spec", return_value=None):
                self.assertEqual(predict.selected_model({}, root), "frozen_near_v1")
            self.assertEqual(predict.selected_model({"NEAR_ORACLE_MODEL": "frozen_near_v2"}, os.path.join(root, "x")),
                             "frozen_near_v2")


class FreezeHelpersTest(unittest.TestCase):
    def test_rows_sha_depends_on_ids_and_labels_only(self):
        a = [{"id": "x", "label": 1, "code": "a"}, {"id": "y", "label": 0, "code": "b"}]
        b = [{"id": "y", "label": 0, "code": "z"}, {"id": "x", "label": 1, "code": "q"}]
        self.assertEqual(freeze.rows_sha256(a), freeze.rows_sha256(b))
        self.assertNotEqual(freeze.rows_sha256(a), freeze.rows_sha256([a[0], {"id": "y", "label": 1}]))

    def test_code_files_cover_analyzer_and_featurize_but_not_tests(self):
        files = freeze.code_files()
        self.assertIn("near/model/featurize.py", files)
        self.assertIn("near/analyzer/detectors.py", files)
        self.assertFalse(any(os.path.basename(f).startswith("test_") for f in files))


if __name__ == "__main__":
    unittest.main()
