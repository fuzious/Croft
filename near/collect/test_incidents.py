import json
import re
import unittest

from near.collect import incidents

SRC = '''
pub struct ExitToNear;

impl Precompile for ExitToNear {
    #[cfg(not(feature = "contract"))]
    fn run(&self, input: &[u8]) -> u32 {
        0
    }

    /// Exit to NEAR.
    #[cfg(feature = "contract")]
    fn run(&self, input: &[u8]) -> u32 {
        if is_static {
            return 1;
        }
        2
    }
}

impl Other {
    fn run(&self) {}
}
'''

TAXONOMY = {
    "non_private_callback", "unhandled_promise_result", "async_reentrancy", "missing_access_control",
    "missing_one_yocto", "signer_auth", "unguarded_upgrade", "unsafe_arithmetic", "precision_rounding",
    "storage_staking", "ft_receiver_trust", "unchecked_receiver", "gas_dos", "oracle_price", "logic_error",
}


class PickFunctionTest(unittest.TestCase):
    def test_selects_by_impl_and_marker_with_doc_and_attributes(self):
        code = incidents.pick_function(SRC, "lib.rs", "run", impl="ExitToNear", contains="is_static")
        self.assertTrue(code.startswith("/// Exit to NEAR."))
        self.assertIn('#[cfg(feature = "contract")]', code)
        self.assertIn("return 1;", code)

    def test_first_match_without_marker(self):
        code = incidents.pick_function(SRC, "lib.rs", "run", impl="Other")
        self.assertIn("fn run(&self) {}", code)

    def test_missing_function_is_none(self):
        self.assertIsNone(incidents.pick_function(SRC, "lib.rs", "nope"))


class BuildRowTest(unittest.TestCase):
    ENTRY = {
        "name": "Example", "date": "2022-04-26", "project": "Aurora", "loss_usd": 0,
        "vuln_class": "logic_error", "summary": "s", "repo": "https://github.com/o/r",
        "vuln_commit": "abc", "fix_commit": "def", "path": "lib.rs", "fn": "run",
        "impl": "ExitToNear", "contains": "is_static", "sources": ["https://x"],
        "rust": True, "confidence": "confirmed", "kind": "bug_bounty", "notes": None,
    }

    def test_row_has_schema_fields_and_snippet(self):
        calls = []

        def fetch(repo, sha, path):
            calls.append((repo, sha, path))
            return SRC

        row = incidents.build_row(self.ENTRY, fetch)
        self.assertEqual(list(row), incidents.FIELDS)
        self.assertIn("return 1;", row["snippet"])
        self.assertEqual(calls, [("https://github.com/o/r", "abc", "lib.rs")])

    def test_mirror_is_used_for_fetching(self):
        calls = []
        entry = dict(self.ENTRY, mirror="https://github.com/m/r")
        incidents.build_row(entry, lambda repo, sha, path: calls.append(repo) or SRC)
        self.assertEqual(calls, ["https://github.com/m/r"])

    def test_no_commit_means_no_fetch_and_no_snippet(self):
        entry = dict(self.ENTRY, vuln_commit=None)
        row = incidents.build_row(entry, lambda *a: self.fail("fetched without a commit"))
        self.assertIsNone(row["snippet"])

    def test_non_rust_entries_keep_no_snippet(self):
        entry = dict(self.ENTRY, rust=False)
        row = incidents.build_row(entry, lambda *a: self.fail("fetched a non-Rust file"))
        self.assertIsNone(row["snippet"])


@unittest.skipUnless(incidents.CURATED.exists(), "curated incidents not unpacked (archives/near_datasets.zip)")
class CuratedListTest(unittest.TestCase):
    def test_entries_are_well_formed(self):
        entries = json.loads(incidents.CURATED.read_text())
        self.assertGreater(len(entries), 10)
        for e in entries:
            with self.subTest(name=e["name"]):
                self.assertTrue(set(incidents.FIELDS) - {"snippet"} <= set(e))
                self.assertRegex(e["date"], r"^\d{4}-\d{2}-\d{2}$")
                self.assertIn(e["confidence"], {"confirmed", "likely"})
                self.assertIn(e["rust"], {True, False, None})
                self.assertTrue(e["vuln_class"] is None or e["vuln_class"] in TAXONOMY)
                self.assertTrue(e["sources"])
                for sha in (e["vuln_commit"], e["fix_commit"]):
                    self.assertTrue(sha is None or re.fullmatch(r"[0-9a-f]{40}", sha), sha)
                if e["vuln_commit"]:
                    self.assertTrue(e["path"] and e["fn"])


if __name__ == "__main__":
    unittest.main()
