import unittest

from near.collect.corpus import dedupe_forks, is_audited, near_sdk_version, repo_from_url, uses_near_sdk


class RepoFromUrlTest(unittest.TestCase):
    def test_github_variants(self):
        self.assertEqual(repo_from_url("https://github.com/Ref-Finance/ref-contracts"), "Ref-Finance/ref-contracts")
        self.assertEqual(repo_from_url("https://github.com/near/near-sdk-rs.git"), "near/near-sdk-rs")
        self.assertEqual(repo_from_url("git@github.com:near/core-contracts.git"), "near/core-contracts")
        self.assertEqual(repo_from_url("https://github.com/near/near-sdk-rs/tree/master/near-sdk"), "near/near-sdk-rs")
        self.assertEqual(repo_from_url("http://www.github.com/a/b/"), "a/b")

    def test_non_github(self):
        self.assertIsNone(repo_from_url("https://gitlab.com/a/b"))
        self.assertIsNone(repo_from_url(None))
        self.assertIsNone(repo_from_url("https://github.com/onlyowner"))


class UsesNearSdkTest(unittest.TestCase):
    def test_detects_imports(self):
        self.assertTrue(uses_near_sdk("use near_sdk::{env, near};\n"))
        self.assertTrue(uses_near_sdk("let a = near_sdk::env::predecessor_account_id();"))
        self.assertTrue(uses_near_sdk("extern crate near_sdk;"))

    def test_ignores_other(self):
        self.assertFalse(uses_near_sdk("use near_primitives::types;\nfn main() {}"))
        self.assertFalse(uses_near_sdk("use my_near_sdkx::foo;"))


class NearSdkVersionTest(unittest.TestCase):
    def test_lock_wins_and_most_common(self):
        lock = '[[package]]\nname = "near-sdk"\nversion = "4.1.1"\n\n[[package]]\nname = "near-sdk-macros"\nversion = "4.1.1"\n'
        self.assertEqual(near_sdk_version(['near-sdk = "4.0.0"'], [lock]), "4.1.1")

    def test_toml_forms(self):
        self.assertEqual(near_sdk_version(['[dependencies]\nnear-sdk = "5.1.0"\n'], []), "5.1.0")
        self.assertEqual(near_sdk_version(['near-sdk = { version = "=4.0.0-pre.4", features = ["unstable"] }'], []), "=4.0.0-pre.4")
        self.assertEqual(near_sdk_version(['[dependencies.near-sdk]\nversion = "3.1.0"\n'], []), "3.1.0")
        self.assertEqual(near_sdk_version(['near-sdk = { git = "https://github.com/near/near-sdk-rs", tag = "4.0.0" }'], []), "git")

    def test_none(self):
        self.assertIsNone(near_sdk_version(['[dependencies]\nserde = "1"\n'], []))
        self.assertIsNone(near_sdk_version(['near-sdk.workspace = true'], []))


class DedupeForksTest(unittest.TestCase):
    def test_drops_fork_when_parent_present_and_keeps_best_orphan_fork(self):
        cands = {
            "near/core-contracts": {"fork_of": None, "stars": 300},
            "alice/core-contracts": {"fork_of": "near/core-contracts", "stars": 1},
            "bob/x": {"fork_of": "carol/x", "stars": 2},
            "dave/x": {"fork_of": "carol/x", "stars": 5},
            "eve/y": {"fork_of": None, "stars": 0},
        }
        self.assertEqual(sorted(dedupe_forks(cands)), ["dave/x", "eve/y", "near/core-contracts"])


class IsAuditedTest(unittest.TestCase):
    def test_audit_paths(self):
        self.assertTrue(is_audited(["src/lib.rs", "audits/2022-blocksec.pdf"]))
        self.assertTrue(is_audited(["docs/Audit/report.md"]))
        self.assertTrue(is_audited(["Halborn_Audit_Report.pdf"]))
        self.assertFalse(is_audited(["src/lib.rs", "README.md", "src/audit_log.rs"]))


if __name__ == "__main__":
    unittest.main()
