"""Per-fold alert counts for the rejected real_hgb research candidate."""
import unittest

from near.intents import train_transactions as tt
from near.intents.audit.holdout_check import run


@unittest.skipUnless(tt.CACHE.exists(), "feature matrix ships in archives/near_transaction_research.zip")
class HoldoutCheckTests(unittest.TestCase):
    def test_fold_alert_counts_match_release_audit(self):
        results = run(tt.CACHE, emit=lambda line: None)
        alerts = {name: (r['combined_medium_plus'], r['collector_medium_plus'], r['collector_high'])
                  for name, r in results.items()}
        self.assertEqual(alerts, {
            'family held out: access_control': (145, 88, 88),
            'family held out: callback_accounting': (23, 0, 0),
            'family held out: resource_exhaustion': (53, 6, 6),
            'family held out: token_spoofing': (132, 594, 594),
            'attacker held out: May fuzzer (2 families)': (140, 125, 122),
            'attacker held out: October exploiter': (23, 0, 0),
            'attacker held out: April actor': (53, 6, 6),
        })


if __name__ == '__main__':
    unittest.main()
