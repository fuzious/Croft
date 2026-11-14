import unittest

import numpy as np

from near.model import eval_common as ec
from near.model import train_classic_v2 as t2


def rows_fixture(n_groups=6):
    rows, i = [], 0
    for g in range(n_groups):
        for k in range(20):
            rows.append({"id": f"c{i}", "label": 0, "source": "corpus", "group": f"g{g}", "path": f"src/f{k % 2}.rs",
                         "fn": "get_value", "attrs": [], "is_near_bindgen": True, "is_public": True, "trait": None,
                         "code": f"pub fn get_value(&self) -> u64 {{\n    let x = self.v{k};\n    x + 1\n}}"})
            i += 1
        for k in range(5):
            rows.append({"id": f"m{i}", "label": 1, "source": "mutation", "group": f"g{g}", "path": "src/lib.rs",
                         "fn": "set_owner", "attrs": [], "is_near_bindgen": True, "is_public": True, "trait": None,
                         "vuln_class": "signer_auth",
                         "code": f"pub fn set_owner(&mut self, o: AccountId) {{\n    assert_eq!(env::signer_account_id(), "
                                 f"self.owner);\n    self.owner{k} = o;\n}}"})
            i += 1
        rows.append({"id": f"a{i}", "label": 1, "source": "audit", "group": f"g{g}", "path": "src/lib.rs",
                     "fn": "set_owner", "attrs": [], "is_near_bindgen": True, "is_public": True, "trait": None,
                     "vuln_class": "signer_auth", "weight": 0.6, "weight_v1": 1.0, "relabel_verdict": "plausible",
                     "code": "pub fn set_owner(&mut self, o: AccountId) {\n    assert_eq!(env::signer_account_id(), "
                             "self.owner);\n    self.owner = o;\n}"})
        i += 1
    return rows


class WeightsTest(unittest.TestCase):
    def test_v1_scheme_uses_pre_relabel_weight(self):
        rows = rows_fixture(2)
        p = dict(t2.V1_PARAMS)
        a = [i for i, r in enumerate(rows) if r["source"] == "audit"]
        w2, w1 = t2.weights(rows, p, "v2"), t2.weights(rows, p, "v1")
        self.assertAlmostEqual(w2[a].sum() / w1[a].sum(), 1.0)  # rescaled to the same real/mutation total
        self.assertTrue(np.allclose(w2[[i for i, r in enumerate(rows) if r["source"] == "corpus"]], 1.0))

    def test_pos_multiplier(self):
        rows = rows_fixture(2)
        y = np.array([r["label"] for r in rows]) == 1
        w = t2.weights(rows, dict(t2.V1_PARAMS, pos=2.0))
        base = t2.weights(rows, dict(t2.V1_PARAMS))
        self.assertTrue(np.allclose(w[y], 2 * base[y]) and np.allclose(w[~y], base[~y]))


class GridTest(unittest.TestCase):
    def test_grid_is_deterministic_and_starts_with_v1(self):
        g = t2.search_grid()
        self.assertEqual(g, t2.search_grid())
        self.assertEqual(g[0], t2.V1_PARAMS)
        self.assertEqual(len(g), 13)

    def test_bucket(self):
        self.assertEqual(t2.bucket({"source": "audit", "label": 1, "relabel_verdict": "confirmed"}), "confirmed")
        self.assertEqual(t2.bucket({"source": "fix_commit", "label": 1, "confidence": "high"}), "fix_commit_v2_high")
        self.assertIsNone(t2.bucket({"source": "corpus", "label": 0}))


class PairedDiffTest(unittest.TestCase):
    def test_identical_is_zero_and_extra_hit_is_positive(self):
        rows = rows_fixture(4)
        s = np.linspace(0, 1, len(rows))
        none = {lvl: np.zeros(len(rows), bool) for lvl in ec.LEVELS}
        d0 = t2.paired_diff(rows, (s, none), (s, none), n_boot=50)
        self.assertEqual((d0["warn_real"]["diff"], d0["warn_real"]["lo"], d0["warn_real"]["hi"]), (0.0, 0.0, 0.0))
        more = {lvl: np.array([r["source"] == "audit" for r in rows]) for lvl in ec.LEVELS}
        d1 = t2.paired_diff(rows, (s, none), (s, more), n_boot=50)
        self.assertEqual(d1["block_real"]["diff"], 1.0)
        self.assertEqual(d1["block_real"]["n"], 4)


class NestedTest(unittest.TestCase):
    def test_nested_cv_scores_every_row_and_separates_the_pattern(self):
        rows = rows_fixture()
        M = t2.featurize(rows, workers=1)
        y = np.array([r["label"] for r in rows])
        t2._G.update(rows=rows, M=t2.with_derived({k: M[k] for k in ("A0", "A1", "D", "X", "T")}), y=y)
        t2.CANDIDATES["_test"] = ("v2", "v2", [dict(t2.V1_PARAMS, top_tokens=50, iters=30)])
        try:
            res = t2.nested("_test", rows, 3, 2, ec.SEED, workers=0, log=lambda s: None)
        finally:
            del t2.CANDIDATES["_test"]
        self.assertTrue(np.isfinite(res["scores"]).all())
        self.assertGreater(ec.metrics(rows, res["scores"])["roc_auc"], 0.9)
        m = ec.metrics(rows, res["scores"], res["decisions"])
        e = t2.extra_metrics(rows, res["scores"], res["decisions"])
        self.assertEqual(e["buckets"]["warn"]["plausible"]["n"], 6)
        self.assertEqual(m["warn"]["recall_real"]["n"], 6)


if __name__ == "__main__":
    unittest.main()
