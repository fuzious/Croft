"""Guard experimental training against temporal leakage and unsafe group fallbacks."""
import pickle
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

import numpy as np

from near.intents import features as ft, model as md
from near.intents.train_candidate import ConditionalForest, main, selection_key, split


class CandidateProtocolTest(unittest.TestCase):
    def test_existing_output_report_stops_before_loading_training_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / 'training_candidate.json'
            report.write_text('existing experiment')
            with patch.object(md, 'load_cache') as load:
                with self.assertRaisesRegex(SystemExit, 'already exists'):
                    main(Path(tmp))
                load.assert_not_called()
            self.assertEqual(report.read_text(), 'existing experiment')

    def test_external_output_still_reads_frozen_baseline_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(md, 'sha256_file', return_value='test-hash') as digest:
                with patch.object(md, 'load_cache', side_effect=ValueError('stop before fitting')):
                    with self.assertRaisesRegex(ValueError, 'stop before fitting'):
                        main(Path(tmp))
                self.assertIn(unittest.mock.call(md.OUT / 'intents_v1.pkl'), digest.call_args_list)
            self.assertTrue((Path(tmp) / 'training_candidate.json').exists())

    def test_time_windows_are_disjoint_and_campaign_month_is_retrospective(self):
        months = np.array(['2026-01', '2026-05', '2026-06', '2026-07',
                           '2026-08', '2026-09', '2026-10', '2026-11'])
        masks = split(months)
        np.testing.assert_array_equal(sum(masks.values()), np.ones(len(months)))
        self.assertEqual(months[masks['fit']].tolist(), ['2026-01', '2026-05'])
        self.assertEqual(months[masks['calibrate']].tolist(), ['2026-06', '2026-07'])
        self.assertEqual(months[masks['select']].tolist(), ['2026-08', '2026-09'])
        self.assertEqual(months[masks['retrospective']].tolist(), ['2026-10', '2026-11'])

    def test_selection_prioritizes_high_alerts_and_breaks_ties_by_simplicity(self):
        def metrics(high, medium, failed):
            return {'selection': {'high': high, 'medium_plus': medium},
                    'selection_failed': {'medium_plus': failed}}
        self.assertLess(selection_key(metrics(0, 20, 10), 2),
                        selection_key(metrics(1, 1, 0), 0))
        self.assertLess(selection_key(metrics(0, 2, 2), 2),
                        selection_key(metrics(0, 3, 0), 0))
        self.assertLess(selection_key(metrics(0, 2, 1), 2),
                        selection_key(metrics(0, 2, 2), 0))
        self.assertLess(selection_key(metrics(0, 2, 1), 0),
                        selection_key(metrics(0, 2, 1), 1))


class ConditionalForestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rng = np.random.default_rng(1)
        cls.X = rng.normal(size=(24, len(ft.FEATURE_KEYS))).astype(np.float32)
        cls.X[:, ft.FEATURE_KEYS.index('n_failed')] = 0
        cls.X[-1, ft.FEATURE_KEYS.index('n_failed')] = 1
        cls.flows = np.array(['deposit'] * 22 + ['withdrawal'] * 2)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            cls.model = ConditionalForest('per_flow_outcome', trees=5, min_rows=4).fit(cls.X, cls.flows)
        # Fixture groups hold fewer rows than IsolationForest's max_samples, so sklearn clips and warns.
        expected = 'max_samples (2048) is greater than the total number of samples'
        if not caught or any(w.category is not UserWarning or not str(w.message).startswith(expected)
                             for w in caught):
            raise AssertionError(f'unexpected warnings while fitting: {[str(w.message) for w in caught]}')

    def test_sparse_outcome_and_unknown_flow_use_fitted_fallback(self):
        probe = self.X[:2].copy()
        probe[:, ft.FEATURE_KEYS.index('n_failed')] = 1
        actual = self.model.score(probe, np.array(['deposit', 'never_seen']))
        expected = [self.model.models['deposit'].score(probe[:1])[0],
                    self.model.models['*'].score(probe[1:])[0]]
        np.testing.assert_array_equal(actual, expected)
        self.assertNotIn('withdrawal', self.model.models)
        np.testing.assert_array_equal(
            self.model.score(probe, np.array(['withdrawal', 'withdrawal'])),
            self.model.models['*'].score(probe))

    def test_outcome_uses_receipt_failure_feature_and_preserves_input_order(self):
        probe = self.X[:2].copy()
        probe[0, ft.FEATURE_KEYS.index('n_failed')] = 3
        self.assertEqual(self.model.groups(probe, np.array(['deposit', 'deposit'])).tolist(),
                         ['deposit:1', 'deposit:0'])
        expected = [self.model.models['deposit'].score(probe[:1])[0],
                    self.model.models['deposit:0'].score(probe[1:])[0]]
        np.testing.assert_array_equal(self.model.score(probe, np.array(['deposit', 'deposit'])), expected)

    def test_pickle_retains_importable_class_and_scores(self):
        restored = pickle.loads(pickle.dumps(self.model))
        self.assertEqual(type(restored).__module__, 'near.intents.train_candidate')
        np.testing.assert_array_equal(restored.score(self.X, self.flows), self.model.score(self.X, self.flows))

    def test_low_anomaly_scores_never_downgrade_rule_alerts(self):
        labels = md.labels_for(np.array([3, 2, 0]), np.zeros(3), {'high': .9, 'medium': .8})
        self.assertEqual(labels.tolist(), ['high', 'medium', 'low'])


if __name__ == '__main__':
    unittest.main()
