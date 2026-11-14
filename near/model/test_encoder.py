import unittest

from near.model import encoder as E


def row(**kw):
    r = {"id": "x", "code": "pub fn f(&mut self) {}", "fn": "f", "impl": "C", "is_near_bindgen": True, "attrs": [],
         "label": 0, "source": "corpus", "group": "g", "path": "src/lib.rs", "severity": None}
    r.update(kw)
    return r


class TruncateTest(unittest.TestCase):
    def test_short_input_is_kept_whole(self):
        self.assertEqual(E.truncate_ids([1, 2], [3, 4, 5], 10), [1, 2, 3, 4, 5])

    def test_long_code_keeps_header_head_and_tail(self):
        out = E.truncate_ids([1, 2], list(range(100, 200)), 10)
        self.assertEqual(len(out), 10)
        self.assertEqual(out[:2], [1, 2])
        self.assertEqual(out[2:6], [100, 101, 102, 103])
        self.assertEqual(out[6:], [196, 197, 198, 199])


class InputTextTest(unittest.TestCase):
    def test_header_carries_attrs_public_and_detector_hits(self):
        code = "#[private]\npub fn on_done(&mut self) {\n    // note\n    let x = env::signer_account_id();\n}"
        head, body = E.input_text(row(code=code, fn="on_done"), strip=True)
        self.assertIn("attrs: private", head)
        self.assertIn("public: 1", head)
        self.assertIn("bindgen: 1", head)
        self.assertNotIn("// note", body)
        self.assertIn("signer_account_id", body)

    def test_comments_kept_without_strip(self):
        _, body = E.input_text(row(code="fn f() {\n    // note\n}"), strip=False)
        self.assertIn("// note", body)

    def test_detector_hit_names_in_header(self):
        code = "pub fn set_owner(&mut self, o: AccountId) {\n    self.owner = o;\n}"
        head, _ = E.input_text(row(code=code, fn="set_owner"), strip=True)
        self.assertIn("hits: privileged_without_auth", head)


class BatchTest(unittest.TestCase):
    def test_batches_cover_rows_once_with_few_shapes_and_token_budget(self):
        import numpy as np
        lengths = np.random.RandomState(0).randint(5, 512, 1000)
        bs = E.batches(lengths, np.arange(1000), 4096, np.random.RandomState(1))
        self.assertEqual(sorted(np.concatenate(bs).tolist()), list(range(1000)))
        pad = [(-(-lengths[b].max() // 64) * 64, len(b)) for b in bs]
        self.assertTrue(all(L * n <= 4096 for L, n in pad))
        self.assertLessEqual(len(set(pad)), 16)


class FoldPlanTest(unittest.TestCase):
    def test_inner_validation_groups_stay_inside_outer_train(self):
        rows = [row(id=str(i), group=f"g{i % 41}") for i in range(600)]
        for tr, val, te in E.fold_plan(rows, 3):
            gs = lambda idx: {rows[i]["group"] for i in idx}
            self.assertFalse(gs(tr) & gs(te) or gs(val) & gs(te) or gs(tr) & gs(val))
            self.assertEqual(len(tr) + len(val) + len(te), 600)


if __name__ == "__main__":
    unittest.main()
