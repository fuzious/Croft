import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

import numpy as np

from near.model import train_candidate as candidate


def row(group, code=None):
    return {"id": group, "group": group, "source": "audit", "label": 1,
            "severity": "high", "path": "src/lib.rs", "is_public": True,
            "code": code or f'pub fn {group}() {{\n let a = 1;\n let b = a+1;\n env::log_str("x");\n}}'}


def metrics(recall, corpus=0.01, fixed=0.1):
    return {level: {"real_recall": {"rate": recall}, "corpus_false_alarm": {"rate": corpus},
                    "fixed_false_alarm": {"rate": fixed}} for level in ("block", "warn")}


class TrainingProtocolTests(unittest.TestCase):
    def test_existing_output_is_not_overwritten_or_retrained(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / candidate.REPORT.name
            report.write_text('{"status": "completed"}')
            with patch("sys.argv", ["train_candidate", "--output-dir", directory]), patch.object(candidate.tc, "load_train") as load:
                with self.assertRaisesRegex(SystemExit, "output exists"):
                    candidate.main()
            load.assert_not_called()
            self.assertEqual(report.read_text(), '{"status": "completed"}')

    def test_formatted_duplicates_stay_together_and_every_row_is_used(self):
        rows = [row(f"g{i}") for i in range(12)]
        rows[1]["code"] = rows[0]["code"].replace("a+1", "a + 1")
        splits = candidate.split_indices(rows)
        self.assertEqual(rows[0]["_experiment_group"], rows[1]["_experiment_group"])
        self.assertEqual(sorted(np.concatenate(list(splits.values())).tolist()), list(range(len(rows))))
        groups = [{rows[i]["_experiment_group"] for i in idx} for idx in splits.values()]
        for i, group in enumerate(groups):
            for other in groups[i+1:]:
                self.assertFalse(group & other)
        self.assertTrue(any(0 in idx and 1 in idx for idx in splits.values()))

    def test_selection_rejects_false_alarm_regression_and_keeps_ties(self):
        scores = {"baseline": metrics(.10), "too_many_corpus_alarms": metrics(.50, corpus=.03),
                  "too_many_fixed_alarms": metrics(.50, fixed=.20), "tied": metrics(.10)}
        self.assertEqual(candidate.select_candidate(scores), "baseline")
        scores["better"] = metrics(.20)
        self.assertEqual(candidate.select_candidate(scores), "better")

    def test_bootstrap_uses_merged_groups_and_paired_differences(self):
        rows = [row("a"), row("b"), row("c")]
        rows[0]["_experiment_group"] = "a+b"
        rows[1]["_experiment_group"] = "a+b"
        base = np.array([False, True, False])
        identical = candidate.paired_group_ci(rows, base, base, repetitions=100)
        self.assertEqual(identical["groups"], 2)
        self.assertEqual(identical["ci95"], [0.0, 0.0])
        self.assertEqual(sum(c["real_positive_n"] for c in identical["group_counts"]), 3)
        gain = candidate.paired_group_ci(rows, np.zeros(3, bool), np.ones(3, bool), repetitions=100)
        self.assertEqual(gain["ci95"], [1.0, 1.0])


if __name__ == "__main__":
    unittest.main()
