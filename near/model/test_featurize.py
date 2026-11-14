import unittest

import numpy as np

from near.analyzer.features import FEATURE_KEYS
from near.model import featurize as fz

CODE = '''/// Owner only.
#[private]
pub fn set_owner(&mut self, owner: AccountId) {
    // comment words must vanish
    assert_eq!(env::predecessor_account_id(), self.owner, "not owner 42");
    self.owner = owner;
}'''


class TokensTest(unittest.TestCase):
    def test_tokens_drop_comments_and_string_contents_and_map_numbers(self):
        toks = fz.code_tokens(CODE)
        self.assertNotIn("comment", toks)
        self.assertNotIn("Owner", toks)
        self.assertNotIn("not", toks)
        self.assertIn("predecessor_account_id", toks)
        self.assertIn("::", toks)
        self.assertIn("S", toks)

    def test_numbers_become_placeholder(self):
        self.assertEqual(fz.code_tokens("x = 1_000 + y"), ["x", "=", "0", "+", "y"])

    def test_char_text_collapses_whitespace_and_comments(self):
        a = fz.char_text("fn a() {\n    x  +  1 // hi\n}")
        self.assertEqual(a, "fn a() { x + 1 }")

    def test_meta_tokens_from_fields(self):
        r = {"attrs": ["private", "payable"], "is_near_bindgen": True, "is_public": True, "trait": "FtCore"}
        self.assertEqual(fz.meta_tokens(r), ["ATTR_private", "ATTR_payable", "BINDGEN", "PUBLIC", "TRAIT"])


class ContextTest(unittest.TestCase):
    def test_code_fallback_sets_public_from_visibility(self):
        r = {"code": CODE, "fn": "set_owner", "attrs": ["private"], "source": "audit", "path": "src/lib.rs"}
        fz.fill_context([r], repos_dir="/nonexistent")
        self.assertTrue(r["is_public"])
        self.assertIsNone(r["trait"])
        self.assertEqual(r["context_from"], "code")

    def test_rows_with_fields_are_kept(self):
        r = {"code": "fn f(&self) {}", "fn": "f", "trait": "T", "is_public": True, "is_payable": False}
        fz.fill_context([r], repos_dir="/nonexistent")
        self.assertEqual((r["trait"], r["is_public"], r["context_from"]), ("T", True, "row"))


class MatrixTest(unittest.TestCase):
    def test_analyzer_matrix_is_signed_log_of_features(self):
        rows = [{"code": CODE, "fn": "set_owner", "attrs": ["private"], "is_public": True, "trait": None,
                 "is_near_bindgen": True, "impl": "C"}] * 3
        X = fz.analyzer_matrix(rows, workers=1)
        self.assertEqual(X.shape, (3, len(FEATURE_KEYS)))
        i = FEATURE_KEYS.index("is_public")
        self.assertAlmostEqual(X[0, i], np.log1p(1.0))

    def test_text_matrices_have_fixed_width(self):
        rows = [{"code": CODE, "attrs": [], "is_public": True}, {"code": "fn g() {}", "attrs": []}]
        T, C = fz.text_matrices(rows, workers=1)
        self.assertEqual(T.shape, (2, fz.TOKEN_DIM))
        self.assertEqual(C.shape, (2, fz.CHAR_DIM))
        self.assertAlmostEqual(float(T[0].multiply(T[0]).sum()), 1.0, places=5)


if __name__ == "__main__":
    unittest.main()
