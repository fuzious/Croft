import unittest

from near.collect import resolve

SRC = '''
#[near_bindgen]
impl Contract {
    /// Withdraw.
    pub fn withdraw(&mut self, amount: U128) {
        self.balance -= amount.0;
    }
}

impl Pool {
    pub fn withdraw(&mut self, amount: u128) -> u128 {
        let fee = amount / 100;
        amount - fee
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn deposit() {}
}

fn deposit(x: u64) -> u64 { x + 1 }
'''


class SlugTest(unittest.TestCase):
    def test_github_and_gitlab(self):
        self.assertEqual(resolve.slug("https://github.com/NearDeFi/burrowland"), "NearDeFi/burrowland")
        self.assertEqual(resolve.slug("https://github.com/o/r.git/"), "o/r")
        self.assertEqual(resolve.slug("https://gitlab.com/orderly-network/protocol"), "orderly-network/protocol")
        self.assertEqual(resolve.slug("gitlab:orderly-network/asset-manager"), "orderly-network/asset-manager")
        self.assertIsNone(resolve.slug(None))

    def test_split_fn(self):
        self.assertEqual(resolve.split_fn("TokenBalance::deposit"), ("deposit", "TokenBalance"))
        self.assertEqual(resolve.split_fn("deposit"), ("deposit", None))
        self.assertEqual(resolve.split_fn("deposit()"), ("deposit", None))


class SeverityTest(unittest.TestCase):
    def test_normalise_and_weight(self):
        self.assertEqual(resolve.norm_severity("Informational"), "info")
        self.assertEqual(resolve.norm_severity("warning"), "low")
        self.assertIsNone(resolve.norm_severity("undetermined"))
        self.assertEqual(resolve.weight("info"), 0.3)
        self.assertEqual(resolve.weight("low"), 0.6)
        self.assertEqual(resolve.weight("critical"), 1.0)
        self.assertEqual(resolve.weight(None), 1.0)


class PickTest(unittest.TestCase):
    def setUp(self):
        self.fns = resolve.extract_functions(SRC, "src/lib.rs")

    def test_unique_non_test(self):
        rec, why = resolve.pick(self.fns, "deposit")
        self.assertEqual(why, "ok")
        self.assertIn("x + 1", rec["code"])

    def test_ambiguous_without_hint(self):
        self.assertEqual(resolve.pick(self.fns, "withdraw")[1], "ambiguous")

    def test_impl_hint(self):
        rec, _ = resolve.pick(self.fns, "withdraw", impl="Pool")
        self.assertIn("fee", rec["code"])

    def test_snippet_hint(self):
        snippet = "pub fn withdraw(&mut self, amount: u128) -> u128 {\nlet fee = amount / 100;\namount - fee\n}"
        rec, _ = resolve.pick(self.fns, "withdraw", snippet=snippet)
        self.assertEqual(rec["impl"], "Pool")

    def test_missing(self):
        self.assertEqual(resolve.pick(self.fns, "nope"), (None, "fn_not_found"))


class AgreesTest(unittest.TestCase):
    CODE = "pub fn withdraw(&mut self, amount: u128) -> u128 {\n    let fee = amount / 100;\n    amount - fee\n}"

    def test_snippet_of_same_fn_must_match(self):
        self.assertTrue(resolve.agrees(self.CODE, "fn withdraw(&mut self, amount: u128) { let fee = amount / 100;",
                                       "withdraw", searched=False))
        other = "fn withdraw(&mut self, pool: Pool) { pool.drain(owner_id); emit_event(log_data) }"
        self.assertFalse(resolve.agrees(self.CODE, other, "withdraw", searched=False))

    def test_snippet_of_other_code(self):
        other = "let alice = context.alice().await?; assert_eq!(4, products.len());"
        self.assertTrue(resolve.agrees(self.CODE, other, "withdraw", searched=False))
        self.assertFalse(resolve.agrees(self.CODE, other, "withdraw", searched=True))
        self.assertTrue(resolve.agrees(self.CODE, None, "withdraw", searched=True))


class SnippetTest(unittest.TestCase):
    def test_complete_function_is_kept(self):
        rec = resolve.snippet_function("pub fn set_owner(&mut self, o: AccountId) {\nself.owner = o;\n}", "set_owner")
        self.assertEqual(rec["fn"], "set_owner")

    def test_truncated_function_is_rejected(self):
        self.assertIsNone(resolve.snippet_function("pub fn set_owner(&mut self) {\nlet x = 1;\n", "set_owner"))

    def test_name_must_match_when_given(self):
        self.assertIsNone(resolve.snippet_function("fn other() {}", "set_owner"))
        self.assertEqual(resolve.snippet_function("fn other() {}", None)["fn"], "other")


class DedupeFindingsTest(unittest.TestCase):
    def test_same_key_and_overlapping_report(self):
        a = {"report": "r1", "repo": "u", "commit": "c", "path": "p", "fn": "f", "title": "T"}
        b = dict(a, report="r2")
        c = {"report": "r3", "repo": "u", "commit": "c", "path": "p", "fn": "f", "title": "Other words",
             "overlaps_report": "r1"}
        d = {"report": "r3", "repo": "u", "commit": "c", "path": "p", "fn": "g", "title": "New",
             "overlaps_report": "r1"}
        kept, dropped = resolve.dedupe_findings([a, b, c, d])
        self.assertEqual(kept, [a, d])
        self.assertEqual(dropped, {"duplicate_finding": 1, "overlapping_report": 1})


class FinalizeTest(unittest.TestCase):
    def row(self, code, label, source="audit"):
        return {"id": resolve.sample_id("g", "p", "f", code + str(label)), "code": code, "label": label,
                "group": "g", "source": source}

    def test_label_one_wins_over_label_zero_for_same_code(self):
        rows = [self.row("fn f() {}", 0), self.row("fn f() {}", 1), self.row("fn g() {}", 0)]
        out, log = resolve.finalize(rows)
        self.assertEqual(sorted((r["code"], r["label"]) for r in out), [("fn f() {}", 1), ("fn g() {}", 0)])
        self.assertEqual(log["label_conflicts"], 1)

    def test_duplicate_ids_collapse(self):
        r = self.row("fn f() {}", 1)
        out, log = resolve.finalize([r, dict(r, source="fix_commit")])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["source"], "audit")
        self.assertEqual(log["duplicate_ids"], 1)


if __name__ == "__main__":
    unittest.main()
