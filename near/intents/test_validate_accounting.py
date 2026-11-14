import gzip
import json
import tempfile
import unittest
from pathlib import Path

from near.intents.validate_accounting import SANDBOX, state_truth, validate

FIXTURES = Path(__file__).resolve().parent / "fixtures/features"


class RecordedStateTruthTests(unittest.TestCase):
    def test_purpose_label_cannot_replace_measured_state(self):
        self.assertIsNone(state_truth({"role": "exploit", "label": "attack"}))
        self.assertFalse(state_truth({"outcome": {"ghost_credit": "0"}, "label": "attack"}))
        self.assertTrue(state_truth({"outcome": {"ghost_credit": str(2**100)}}))

    def test_malformed_state_amount_is_not_counted_as_zero(self):
        for value in (True, -1, "-1", "1.5", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                state_truth({"outcome": {"ghost_credit": value}})


def recorded(name, **meta):
    with gzip.open(FIXTURES / f"{name}.json.gz", "rt") as stream:
        tx = json.load(stream)
    tx["_meta"] = meta
    return tx


def write_inputs(data_dir, inputs):
    for name in (*SANDBOX, "labelled.jsonl.gz", "normals.jsonl.gz"):
        path = data_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(path, "wt") as stream:
            stream.writelines(json.dumps(tx) + "\n" for tx in inputs.get(name, []))


class RecordedInputValidationTests(unittest.TestCase):
    def inputs(self):
        return {
            "synthetic/attacks.jsonl.gz": [
                recorded("exploit_2GQ2zQ", verifier_version="v0.4.2", outcome={"ghost_credit": "5"}),
                recorded("normal_deposit_ft_transfer_call", verifier_version="v0.4.2",
                         outcome={"ghost_credit": "7"}),
            ],
            "synthetic/benign.jsonl.gz": [
                recorded("normal_deposit_mt_deposit_call", verifier_version="v0.4.2", outcome={"ghost_credit": "0"}),
            ],
            "synthetic/fixed_v0.4.3-backport.jsonl.gz": [
                recorded("normal_delegate", verifier_version="v0.4.3-backport"),
            ],
            "labelled.jsonl.gz": [
                recorded("exploit_3k91uD", role="exploit"),
                recorded("normal_execute_intents", role="normal"),
            ],
            "normals.jsonl.gz": [recorded("normal_withdrawal_ft_withdraw")],
        }

    def test_state_positive_row_without_high_finding_is_a_measured_disagreement(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_inputs(Path(tmp), self.inputs())
            report = validate(Path(tmp))
        no_high = recorded("normal_deposit_ft_transfer_call")["transaction"]["hash"]
        self.assertEqual(report["sandbox"]["measured_state_disagreements"],
                         [{"tx_hash": no_high, "state_positive": True, "high_finding": False}])
        self.assertEqual(report["sandbox"]["state_measurements"], {"positive": 2, "zero": 1, "not_measured": 1})
        groups = report["groups"]
        self.assertEqual((groups["sandbox_state_positive"]["n"], groups["sandbox_state_positive"]["high_findings"]),
                         (2, 1))
        self.assertEqual(groups["sandbox_other_unpatched"]["n"], 1)
        self.assertEqual(groups["sandbox_patched"]["state_not_measured"], 1)
        self.assertEqual((groups["real_exploits"]["n"], groups["real_exploits"]["high_findings"]), (1, 1))
        self.assertEqual(groups["historical_normals"]["n"], 1)
        self.assertEqual(report["unique_transactions_scored"], 6)

    def test_duplicate_transaction_across_inputs_is_rejected(self):
        inputs = self.inputs()
        inputs["normals.jsonl.gz"].append(recorded("exploit_3k91uD"))
        with tempfile.TemporaryDirectory() as tmp:
            write_inputs(Path(tmp), inputs)
            with self.assertRaisesRegex(ValueError, "Duplicate transaction in validation inputs"):
                validate(Path(tmp))
