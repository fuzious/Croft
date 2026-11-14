import unittest

import numpy as np

from near.model import freeze
from near.model import score_sealed as ss


def row(i, **kw):
    r = {"id": f"r{i}", "group": "g", "norm_hash": f"h{i}", "label": 0, "source": "corpus", "severity": None,
         "vuln_class": None, "date": None, "finding": None, "evidence": None}
    r.update(kw)
    return r


class DisjointTest(unittest.TestCase):
    def test_reports_shared_ids_groups_and_norm_hashes(self):
        train = [row(1, group="a"), row(2, group="b")]
        self.assertEqual(ss.check_disjoint(train, [row(3, group="c")]), [])
        probs = ss.check_disjoint(train, [row(1, group="c"), row(4, group="b"), row(5, group="d", norm_hash="h2")])
        self.assertEqual(len(probs), 3)
        self.assertTrue(any("id" in p for p in probs) and any("group" in p for p in probs)
                        and any("norm_hash" in p for p in probs))


class BreakdownTest(unittest.TestCase):
    def test_rates_by_key_within_mask(self):
        rows = [row(0, source="audit", label=1), row(1, source="audit", label=1), row(2, source="incident", label=1),
                row(3)]
        hit = np.array([True, False, True, True])
        mask = np.array([r["label"] == 1 for r in rows])
        out = ss.rates_by(rows, hit, mask, lambda r: r["source"])
        self.assertEqual((out["audit"]["k"], out["audit"]["n"]), (1, 2))
        self.assertEqual((out["incident"]["k"], out["incident"]["n"]), (1, 1))
        self.assertNotIn("corpus", out)

    def test_time_split_is_real_rows_dated_2025_or_later(self):
        self.assertTrue(ss.in_time_split(row(0, source="audit", label=1, date="2025-01-01")))
        self.assertFalse(ss.in_time_split(row(0, source="audit", label=1, date="2024-12-31")))
        self.assertFalse(ss.in_time_split(row(0, source="mutation", label=1, date="2025-06-01")))
        self.assertFalse(ss.in_time_split(row(0, source="audit", label=1, date=None)))


class ContractLevelTest(unittest.TestCase):
    def test_file_mode_counts_clean_files_inside_groups_with_real_vulnerabilities(self):
        body = "pub fn f(&mut self) {\n    let a = 1;\n    self.a = a;\n}"
        rows = [row(0, source="audit", label=1, path="src/a.rs", code=body, is_public=True),
                row(1, path="src/a.rs", code=body, is_public=True),
                row(2, path="src/b.rs", code=body, is_public=True),
                row(3, path="src/c.rs", code=body, is_public=True)]
        hit = np.array([False, True, True, False])
        by_group = freeze.contract_level(rows, hit)
        self.assertEqual(by_group["clean_files"]["n"], 0)
        self.assertEqual((by_group["real_vuln_files"]["k"], by_group["real_vuln_files"]["n"]), (1, 1))
        by_file = freeze.contract_level(rows, hit, clean_by="file")
        self.assertEqual((by_file["clean_files"]["k"], by_file["clean_files"]["n"]), (1, 2))


class IncidentTest(unittest.TestCase):
    def test_outcome_is_the_best_level_reached_by_any_vulnerable_row(self):
        rows = [row(0, source="incident", label=1, finding="hack A", date="2023-01-01"),
                row(1, source="incident", label=1, finding="hack A", date="2023-01-01"),
                row(2, source="incident", label=1, finding="hack B"),
                row(3, source="incident", label=0, finding="hack B"),
                row(4, source="incident", label=1, finding="hack C")]
        scores = np.array([0.4, 0.95, 0.5, 0.99, 0.1])
        out = {o["incident"]: o for o in ss.incident_outcomes(rows, scores, {"block": 0.9, "warn": 0.45})}
        self.assertEqual(out["hack A"]["outcome"], "block")
        self.assertEqual(out["hack B"]["outcome"], "warn")
        self.assertEqual(out["hack C"]["outcome"], "missed")
        self.assertEqual(out["hack B"]["fixed_version_alarm"], "block")


if __name__ == "__main__":
    unittest.main()
