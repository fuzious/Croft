import unittest

from near.collect.fix_commits import is_contract_path, match_keywords, parse_log


class MatchKeywordsTest(unittest.TestCase):
    def test_security_words(self):
        self.assertEqual(match_keywords("Fix reentrancy in withdraw callback"), ["fix_callback", "fix_reentr", "fix_withdraw"])
        self.assertIn("audit", match_keywords("Address audit findings from BlockSec"))
        self.assertIn("cve", match_keywords("patch CVE-2021-1234"))
        self.assertIn("high_severity", match_keywords("resolve High Severity issue"))
        self.assertIn("fix_yocto", match_keywords("fix: assert one yocto on transfer"))

    def test_ignores_noise(self):
        self.assertEqual(match_keywords("add project overview readme"), [])
        self.assertEqual(match_keywords("fix typo in docs"), [])
        self.assertEqual(match_keywords("bump version"), [])


class IsContractPathTest(unittest.TestCase):
    def test_paths(self):
        roots = {""}
        self.assertTrue(is_contract_path("contracts/token/src/lib.rs", {"contracts/token"}, set()))
        self.assertFalse(is_contract_path("frontend/src/main.rs", {"contracts/token"}, set()))
        self.assertTrue(is_contract_path("frontend/src/main.rs", {"contracts/token"}, {"frontend/src/main.rs"}))
        self.assertTrue(is_contract_path("src/lib.rs", roots, set()))
        self.assertFalse(is_contract_path("contracts/token/Cargo.toml", {"contracts/token"}, set()))
        self.assertFalse(is_contract_path("contracts/token-other/src/lib.rs", {"contracts/token"}, set()))


class ParseLogTest(unittest.TestCase):
    def test_parse(self):
        out = ("\x1eabc123\x1fp1 p2\x1f2022-03-04\x1fFix overflow\n\nbody\x1f\n\nsrc/lib.rs\nREADME.md\n"
               "\x1edef456\x1f\x1f2021-01-01\x1fInitial\x1f\n\nsrc/a.rs\n")
        rows = parse_log(out)
        self.assertEqual(rows[0], {"commit": "abc123", "parent": "p1", "date": "2022-03-04",
                                   "message": "Fix overflow\n\nbody", "files": ["src/lib.rs", "README.md"]})
        self.assertEqual(rows[1]["parent"], None)
        self.assertEqual(rows[1]["files"], ["src/a.rs"])


if __name__ == "__main__":
    unittest.main()
