"""Prevent cross-family, temporal and output-state leakage in research training."""
import json
from pathlib import Path
import pickle
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from near.intents import train_transactions as train


class TransactionTrainingTests(unittest.TestCase):
    def test_unsupported_real_positive_never_reaches_model_fit(self):
        def row(i, source='normal', month='2026-05', **extra):
            return {'id': str(i), 'source_kind': source, 'month': month, 'family': 'callback_accounting',
                    'label': 0, 'partition': None, 'excluded': None, 'supported': True,
                    'history_complete': True, 'observable': True, 'flow': 'deposit',
                    'rule_severity': 0, 'failed': False, 'source': 'collector', 'actor_group': str(i), **extra}
        rows = [row(i, month=m) for i, m in enumerate(['2026-05', '2026-06', '2026-08', '2026-10'])]
        rows += [row(4, 'real', label=1), row(5, 'real', label=1, supported=False)]
        for part in ('train', 'validation', 'test'):
            rows += [row(len(rows), 'synthetic', partition=part, label=1),
                     row(len(rows) + 1, 'synthetic', partition=part, label=0)]
        X = np.arange(len(rows), dtype=np.float32)[:, None]
        X[5] = 999
        data = {'X': X, 'base_X': X, 'records': rows, 'inputs': {}, 'code_sha256': {},
                'feature_keys': ['dummy'], 'accounting_severity': np.zeros(len(rows), int),
                'history_severity': np.zeros(len(rows), int), 'history_features': np.zeros((len(rows), 10))}
        fitted_real_inputs = []
        def fit(kind, normal, real, synthetic, targets):
            fitted_real_inputs.append(real.copy())
            return {'kind': kind, 'estimator': None}
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(train, 'fit_candidate', side_effect=fit),
            patch.object(train, 'candidate_scores', side_effect=lambda model, X: np.zeros(len(X))),
            patch.object(train.md, 'load_artifact', return_value={'thresholds': {'high': 1., 'medium': .5}}),
            patch.object(train.md, 'score_matrix', side_effect=lambda model, X, flows: np.zeros(len(X))),
            patch.object(train, 'domain_audit', return_value={'status': 'not_available'}),
            patch.object(train, 'evaluate_external', return_value={}),
            patch('builtins.print'),
        ):
            report = {}
            train.train_and_evaluate(data, report, Path(directory) / 'report.json', Path(directory) / 'candidate.pkl')
        self.assertTrue(fitted_real_inputs)
        self.assertTrue(all(not np.any(values == 999) for values in fitted_real_inputs))
        self.assertEqual(report['real_case_coverage']['all_labelled_positives'], 2)
        self.assertEqual(report['real_case_coverage']['supported_complete'], 1)
        self.assertEqual(report['real_case_coverage']['outside_classification_scope'][0]['id'], '5')

    def test_canonical_family_unifies_generated_positive_and_benign(self):
        rows = [
            {'family': 'callback_accounting', 'attack_family': 'notify_refund_overask', 'label': 1},
            {'family': 'callback_accounting', 'benign_family': 'benign_mt_deposit_notify', 'label': 0},
            {'family': 'token_spoofing', 'attack_family': 'token_spoof_direct_on_transfer', 'label': 1},
        ]
        families = np.array([train.attack_family(r) for r in rows])
        self.assertEqual(families.tolist(), ['callback_accounting', 'callback_accounting', 'token_spoofing'])
        self.assertEqual(np.flatnonzero(families != 'callback_accounting').tolist(), [2])

    def test_temporal_partitions_are_disjoint(self):
        months = ['2026-05', '2026-06', '2026-07', '2026-08', '2026-09', '2026-10']
        masks = train.temporal_masks(months)
        np.testing.assert_array_equal(sum(masks.values()), np.ones(len(months)))
        self.assertEqual(np.flatnonzero(masks['calibration']).tolist(), [1, 2])
        self.assertEqual(np.flatnonzero(masks['retrospective']).tolist(), [5])

    def test_synthetic_actor_and_template_overlap_are_rejected(self):
        a = {'source_kind': 'synthetic', 'partition': 'train', 'actor_group': 'a', 'template_id': 'ta'}
        b = {'source_kind': 'synthetic', 'partition': 'test', 'actor_group': 'b', 'template_id': 'tb'}
        train.check_synthetic_splits([a, b])
        for key in ('actor_group', 'template_id'):
            with self.assertRaisesRegex(ValueError, 'overlaps'):
                train.check_synthetic_splits([a, dict(b, **{key: a[key]})])

    def test_single_class_controls_are_not_balanced_accuracy(self):
        rows = [{'family': 'benign_failure', 'label': 0, 'actor_group': 'a'}]
        metric = train.synthetic_metrics(np.array(['low']), rows)['benign_failure']
        self.assertIsNone(metric['balanced_accuracy'])
        self.assertEqual(metric['specificity'], 1.)

    def test_alert_budget_precedes_candidate_recall(self):
        def metric(high, medium, recall):
            return {'selection_normals': {'high': high, 'medium_plus': medium},
                    'real_family_macro_recall': recall, 'synthetic_validation_balanced_accuracy': .9}
        candidates = {'extended_iforest': metric(0, 2, .5), 'real_hgb': metric(1, 1, 1.)}
        self.assertEqual(train.select_candidate(candidates, {'high': 0, 'medium_plus': 2}), 'extended_iforest')
        self.assertIsNone(train.select_candidate(candidates, {'high': 0, 'medium_plus': 1}))

    def test_calibration_preserves_high_and_medium_budgets(self):
        scores = np.arange(10000) / 10000
        thresholds = train.calibrate(scores)
        self.assertLessEqual(int((scores >= thresholds['high']).sum()), 1)
        self.assertLessEqual(int((scores >= thresholds['medium']).sum()), 10)

    def test_revealed_evaluation_cannot_be_retrained_in_place(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / train.REPORT.name
            original = {'status': 'selection_frozen', 'protocol_sha256': train.digest(train.PROTOCOL)}
            path.write_text(json.dumps(original))
            with patch('sys.argv', ['train_transactions', 'run', '--output-dir', directory]), patch.object(train, 'extract_features') as extract:
                with self.assertRaisesRegex(SystemExit, 'already started'):
                    train.main()
                extract.assert_not_called()
            self.assertEqual(json.loads(path.read_text()), original)

    def test_candidate_digest_checked_before_unpickling(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'candidate.pkl'
            path.write_bytes(pickle.dumps({'research_only': True}))
            manifest = {'sha256': train.md.sha256_file(path), 'feature_code_sha256': {},
                        'inference_code_sha256': train.md.sha256_file(train.__file__)}
            path.with_suffix('.json').write_text(json.dumps(manifest))
            self.assertTrue(train.load_candidate(path)['research_only'])
            path.write_bytes(b'corrupted')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                train.load_candidate(path)


if __name__ == '__main__':
    unittest.main()
