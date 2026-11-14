import tempfile
import unittest
from pathlib import Path

from near.service import blocklist


class BlocklistTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "blocklist.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_unknown_account_is_clear(self):
        self.assertEqual(blocklist.lookup("a.near", self.path), {"blocked": False, "confirmed": [], "pending": 0})

    def test_report_is_pending_until_confirmed_and_persists(self):
        r = blocklist.add_report("bad.near", "https://example.com/post", path=self.path)
        self.assertEqual((r["id"], r["status"]), (0, "pending"))
        self.assertEqual(blocklist.lookup("bad.near", self.path)["pending"], 1)
        self.assertFalse(blocklist.lookup("bad.near", self.path)["blocked"])
        blocklist.set_status(0, "confirmed", self.path)
        got = blocklist.lookup("bad.near", self.path)
        self.assertTrue(got["blocked"])
        self.assertEqual((got["pending"], got["confirmed"][0]["evidence_url"]), (0, "https://example.com/post"))
        self.assertFalse(blocklist.lookup("good.near", self.path)["blocked"])

    def test_dismissed_report_does_not_count(self):
        blocklist.add_report("x.near", "https://e.com/1", path=self.path)
        blocklist.set_status(0, "dismissed", self.path)
        self.assertEqual(blocklist.lookup("x.near", self.path), {"blocked": False, "confirmed": [], "pending": 0})

    def test_confirmed_on_report(self):
        blocklist.add_report("y.near", "https://e.com/2", evidence_sha256="ab" * 32, confirmed=True, path=self.path)
        self.assertTrue(blocklist.lookup("y.near", self.path)["blocked"])

    def test_unknown_report_id_and_bad_status(self):
        with self.assertRaises(KeyError):
            blocklist.set_status(7, "confirmed", self.path)
        blocklist.add_report("z.near", "https://e.com/3", path=self.path)
        with self.assertRaises(ValueError):
            blocklist.set_status(0, "maybe", self.path)


if __name__ == "__main__":
    unittest.main()
