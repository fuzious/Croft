import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from near.intents.collect_cases import checked_transactions, collect_unknown, write_records, main


def tx(h, signer='user.near', receipts=None):
    return {'transaction': {'hash': h, 'signer_id': signer}, 'receipts': receipts or [],
            'execution_outcome': {'block_timestamp': '1794677625123583897'}}


class FakeClient:
    def __init__(self, transactions):
        self.transactions = transactions
        self.calls = 0

    def post(self, path, body):
        self.calls += 1
        return {'transactions': self.transactions}

    def account_page(self, account, **kwargs):
        return {'account_txs': [{'transaction_hash': t['transaction']['hash']} for t in self.transactions],
                'resume_token': None}


class CollectionTests(unittest.TestCase):
    def test_output_dir_refuses_overwrite_before_reading_data_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'cases'
            output.mkdir()
            manifest = output / 'manifest.json'
            manifest.write_text('{"preserve":true}')
            with patch('sys.argv', ['collect_cases', '--output-dir', directory]), \
                    patch('near.intents.collect_cases.load_labels') as labels:
                with self.assertRaisesRegex(SystemExit, 'output exists'):
                    main()
            labels.assert_not_called()
            self.assertEqual(manifest.read_text(), '{"preserve":true}')

    def test_unknowns_never_become_negatives_and_known_signers_are_excluded(self):
        client = FakeClient([tx('new'), tx('bad', 'attacker.near')])
        rows, exclusions, _ = collect_unknown(client, 2, set(), set(), {'attacker.near'})
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]['_meta']['label'])
        self.assertEqual(rows[0]['_meta']['ground_truth'], 'unknown')
        self.assertEqual(exclusions['labelled_signer'], 1)

    def test_fullest_duplicate_is_retained_and_unrequested_rows_refused(self):
        client = FakeClient([tx('a'), tx('a', receipts=[{'receipt': 'fuller'}])])
        self.assertEqual(len(checked_transactions(client, ['a'])[0]['receipts']), 1)
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            checked_transactions(FakeClient([tx('surprise')]), ['a'])

    def test_existing_hashes_are_not_requested(self):
        client = FakeClient([tx('known')])
        rows, _, _ = collect_unknown(client, 1, {'known'}, set(), set())
        self.assertEqual(rows, [])
        self.assertEqual(client.calls, 0)

    def test_collection_budget_and_exclusive_reproducible_output(self):
        with self.assertRaises(ValueError):
            collect_unknown(FakeClient([]), 1001, set(), set(), set())
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / 'a.gz', Path(directory) / 'b.gz'
            write_records(first, [tx('a')])
            write_records(second, [tx('a')])
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(json.loads(gzip.decompress(first.read_bytes())), tx('a'))
            with self.assertRaises(FileExistsError):
                write_records(first, [])


if __name__ == '__main__':
    unittest.main()
