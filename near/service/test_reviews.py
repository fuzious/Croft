import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from near.service import app as service, reviews

TX = '3k91uDpUiezxUe7hBgAR7kc3TBkToMZKGAiv6GqbtKiC'


class HumanReviewTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'ORACLE_REVIEW_DB': self.temp.name + '/reviews.sqlite3'})
        self.env.start()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.env.stop)
        self.client = TestClient(service.app)
        self.evidence = {'tx_hash': TX, 'assessment': 'suspicious', 'label': 'medium',
                         'risk': 0.5, 'signer_id': 'sender.near', 'receipts_complete': True}

    def test_score_automatically_queues_and_preserves_decision_on_rescore(self):
        with patch.object(service.intents, 'model_info', return_value={'version': 'test'}), \
                patch.object(service.intents, 'score_hash', return_value=self.evidence):
            response = self.client.post('/v1/transactions/score', json={'tx_hash': TX})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(self.client.get('/v1/reviews').json()['items']), 1)
            response = self.client.patch('/v1/reviews/' + TX, json={
                'status': 'dismissed', 'note': 'Expected operational behavior.'})
            self.assertEqual(response.status_code, 200)
            self.client.post('/v1/intents/score', json={'tx_hash': TX})
        rows = self.client.get('/v1/reviews').json()['items']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status'], 'dismissed')
        self.assertEqual(rows[0]['note'], 'Expected operational behavior.')
        self.assertIsNotNone(rows[0]['reviewed_at'])

    def test_scan_queues_high_and_suspicious_but_not_clean_or_unsupported(self):
        txs = [{**self.evidence, 'tx_hash': str(i), 'assessment': a} for i, a in enumerate(
            ('malicious_pattern', 'suspicious', 'no_known_pattern', 'unsupported', 'inconclusive'))]
        with patch.object(service.intents, 'model_info', return_value={}), \
                patch.object(service.intents, 'recent_activity', return_value={
                    'txs': txs, 'n_scored': 5, 'n_index_rows': 5}):
            response = self.client.post('/v1/protocols/scan', json={'account_id': 'intents.near'})
            self.assertEqual(response.status_code, 200)
        rows = self.client.get('/v1/reviews').json()['items']
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row['account_id'] == 'intents.near' for row in rows))

    def test_decision_validation_missing_case_and_reopen(self):
        reviews.enqueue(self.evidence)
        for data in ({'status': 'allow', 'note': 'No'}, {'status': 'confirmed', 'note': '  '}):
            self.assertEqual(self.client.patch('/v1/reviews/' + TX, json=data).status_code, 422)
        decision = {'status': 'confirmed', 'note': 'Receipt evidence confirms finding.'}
        self.assertEqual(self.client.patch('/v1/reviews/missing', json=decision).status_code, 404)
        self.assertEqual(self.client.patch('/v1/reviews/' + TX, json=decision).json()['status'], 'confirmed')
        decision.update(status='pending', note='Needs a second review.')
        self.assertEqual(self.client.patch('/v1/reviews/' + TX, json=decision).json()['status'], 'pending')

    def test_demo_is_explicit_idempotent_and_separate_from_live_cases(self):
        self.assertEqual(self.client.get('/v1/reviews').json()['items'], [])
        self.assertEqual(self.client.get('/human/').status_code, 200)
        first = self.client.post('/v1/reviews/demo').json()['items']
        second = self.client.post('/v1/reviews/demo').json()['items']
        self.assertEqual(len(first), 4)
        self.assertEqual(len(second), 4)
        self.assertTrue(all(i['demo'] and i['id'].startswith('demo:') for i in first))
        reviews.enqueue(self.evidence)
        self.assertEqual(len(self.client.get('/v1/reviews').json()['items']), 5)


if __name__ == '__main__':
    unittest.main()
