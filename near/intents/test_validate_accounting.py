import unittest

from near.intents.validate_accounting import state_truth


class RecordedStateTruthTests(unittest.TestCase):
    def test_purpose_label_cannot_replace_measured_state(self):
        self.assertIsNone(state_truth({"role": "exploit", "label": "attack"}))
        self.assertFalse(state_truth({"outcome": {"ghost_credit": "0"}, "label": "attack"}))
        self.assertTrue(state_truth({"outcome": {"ghost_credit": str(2**100)}}))

    def test_malformed_state_amount_is_not_counted_as_zero(self):
        for value in (True, -1, "-1", "1.5", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                state_truth({"outcome": {"ghost_credit": value}})
