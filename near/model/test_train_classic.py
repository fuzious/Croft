import json
import os
import tempfile
import unittest

import numpy as np

from near.model import eval_common as ec
from near.model import train_classic as tc


def rows_fixture(n_groups=6):
    rows, i = [], 0
    for g in range(n_groups):
        for k in range(20):
            rows.append({"id": f"c{i}", "label": 0, "source": "corpus", "group": f"g{g}", "path": f"src/f{k % 2}.rs",
                         "fn": "get", "attrs": [], "is_near_bindgen": True, "is_public": True, "trait": None,
                         "code": f"pub fn get(&self) -> u64 {{ self.v{k} }}"})
            i += 1
        for k in range(5):
            rows.append({"id": f"m{i}", "label": 1, "source": "mutation", "group": f"g{g}", "path": "src/lib.rs",
                         "fn": "set_owner", "attrs": [], "is_near_bindgen": True, "is_public": True, "trait": None,
                         "vuln_class": "signer_auth",
                         "code": f"pub fn set_owner(&mut self, o: AccountId) {{ assert_eq!(env::signer_account_id(), "
                                 f"self.owner); self.owner{k} = o; }}"})
            i += 1
    return rows


class LoadTrainTest(unittest.TestCase):
    def test_drops_ids_and_checks_sha(self):
        with tempfile.TemporaryDirectory() as d:
            train = os.path.join(d, "train_v1.jsonl")
            with open(train, "w") as f:
                for r in ({"id": "a"}, {"id": "b"}):
                    f.write(json.dumps(r) + "\n")
            drop = os.path.join(d, "drop.json")
            with open(drop, "w") as f:
                json.dump({"train_sha256": tc.sha256(train), "ids": ["b"]}, f)
            rows, info = tc.load_train(train, drop, full=train)
            self.assertEqual([r["id"] for r in rows], ["a"])
            self.assertEqual(info["dropped"], 1)
            with open(drop, "w") as f:
                json.dump({"train_sha256": "0" * 64, "ids": ["b"]}, f)
            with self.assertRaises(SystemExit):
                tc.load_train(train, drop, full=train)

    def test_refuses_test_files(self):
        with self.assertRaises(SystemExit):
            tc.load_train("near/data/test_v1.jsonl")


class ModelsTest(unittest.TestCase):
    def test_each_kind_separates_an_obvious_pattern(self):
        rows = rows_fixture()
        A, T, C = tc.featurize_rows(rows, workers=0)
        y = np.array([r["label"] for r in rows])
        w = ec.sample_weights(rows)
        for kind, p in (("logreg", {"C": 1.0, "char": 1.0, "info": 0.3}),
                        ("sgd", {"alpha": 1e-4, "char": 0.0, "info": 0.3}),
                        ("hgb", {"lr": 0.1, "leaves": 7, "info": 0.3, "svd": 4, "top_tokens": 20, "iters": 30})):
            m = tc.fit_model(kind, p, A, T, C, y, w)
            s = tc.predict_model(m, A, T, C)
            self.assertGreater(s[y == 1].min(), s[y == 0].max(), kind)

    def test_select_returns_grid_member_and_full_oof(self):
        rows = rows_fixture()
        A, T, C = tc.featurize_rows(rows, workers=0)
        tc._G.update(rows=rows, A=A, T=T, C=C, y=np.array([r["label"] for r in rows]))
        tr = np.arange(len(rows))
        folds = ec.group_folds(rows, 3, seed=0)
        grid = tc.GRIDS["sgd"]
        tc.GRIDS["sgd"] = grid[:2]
        try:
            p, oof, table = tc.select("sgd", rows, tr, folds, workers=0)
        finally:
            tc.GRIDS["sgd"] = grid
        self.assertIn(p, grid[:2])
        self.assertFalse(np.isnan(oof).any())
        self.assertEqual(len(table), 2)


if __name__ == "__main__":
    unittest.main()
