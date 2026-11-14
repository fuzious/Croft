"""Offline checks of scenario helpers against recorded sandbox output."""

import json
import unittest
from pathlib import Path

from near.intents.synthetic import scenarios

FIXTURES = Path(__file__).parent / "fixtures"


class EventLogSizeTest(unittest.TestCase):
    def test_mint_log_size_matches_recorded_contract_log(self):
        status = json.loads((FIXTURES / "sandbox_exploit_log_overflow.json").read_text())["status"]
        mint = [l for ro in status["receipts_outcome"] for l in ro["outcome"]["logs"] if '"mt_mint"' in l][0]
        owner = json.loads(mint[len("EVENT_JSON:"):])["data"][0]["owner_id"]
        dust = "4444119_" + "E" * 93
        ids = [scenarios.OMNI_PREFIX + dust] * 97 + [scenarios.OMNI_PREFIX + "usdt_main"]
        amounts = [1] * 97 + [10**21]
        self.assertEqual(scenarios.event_log_len("mt_mint", owner, ids, amounts, "deposit"), len(mint))

    def test_burn_log_grows_with_refund_digits(self):
        ids = [scenarios.OMNI_PREFIX + "x" * 100] * 50
        small = scenarios.event_log_len("mt_burn", "a" * 64, ids, [1] * 50, "refund")
        big = scenarios.event_log_len("mt_burn", "a" * 64, ids, [10**36] * 50, "refund")
        self.assertEqual(big - small, 36 * 50)


if __name__ == "__main__":
    unittest.main()
