"""Fetch source-confirmed NEAR cases and a bounded, explicitly unlabelled traffic sample.

python -m near.intents.collect_cases --unknown-count 500
Sources establish transaction roles; account association alone never creates an attack label.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

from near.intents.collect import (ATTACKERS, DATA, LABELS, attacker_ids, attach_meta,
                                 exclusion_reason, iter_jsonl_gz, labelled_signers,
                                 load_labels, now_iso, tx_month)
from near.intents.fastnear import FastNear, Pacer, tx_hash, unique

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / 'near/intents/fixtures/cases_v2'
SOURCED_CASES = (
    {'tx_hash': 'GcXEKmcJrfGVkPxZR89nNrmXqbR5VjTii45X7wzCfnFT',
     'campaign': 'rhea_margin_circular_swap_2026_04', 'role': 'exploit', 'label': 1,
     'protocol': 'contract.main.burrow.near', 'intents_supported': False,
     'source_url': 'https://blocksec.com/blog/weekly-web3-security-incident-roundup-apr-13-apr-19-2026',
     'attribution': 'BlockSec original incident analysis explicitly identifies this transaction as its Rhea attack example.'},
    {'tx_hash': '44tWhQmmkTJgchgFVkYpPrgyKvaH7wRLu1jZWXD3Du1x',
     'campaign': 'rhea_margin_circular_swap_2026_04', 'role': 'exploit', 'label': 1,
     'protocol': 'contract.main.burrow.near', 'intents_supported': False,
     'source_url': 'https://www.quillaudits.com/blog/hack-analysis/rhea-finance-hack',
     'attribution': 'QuillAudits original incident analysis explicitly lists this hash as an example attack transaction.'},
    {'tx_hash': '92Gq7zehKPwSSnpoZ7LGGtSmgmBb4wP2XNDVJqUZRGqz',
     'campaign': 'skyward_duplicate_redemption_2022_11', 'role': 'exploit', 'label': 1,
     'protocol': 'skyward.near', 'intents_supported': False,
     'source_url': 'https://twitter.com/BlockSecTeam/status/1587998109648683010',
     'source_mirror': 'https://threadreaderapp.com/thread/1587998109648683010.html',
     'attribution': 'BlockSec original analyst thread links this transaction as the Skyward exploit; mirror preserves the link.'},
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_records(path: Path, rows: list[dict]) -> None:
    """Deterministic gzip, with exclusive creation so an evaluation sample cannot be replaced silently."""
    raw = ''.join(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n' for row in rows).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(gzip.compress(raw, mtime=0))


def checked_transactions(client: FastNear, hashes: list[str]) -> list[dict]:
    """Keep the fullest duplicate; never accept unrelated API response rows."""
    allowed = set(hashes)
    found = {}
    for start in range(0, len(hashes), 20):
        response = client.post('/transactions', {'tx_hashes': hashes[start:start + 20]})
        if not isinstance(response, dict) or not isinstance(response.get('transactions'), list):
            raise ValueError('transaction response has no list')
        for tx in response['transactions']:
            if tx is None:
                continue
            h = tx_hash(tx)
            if h not in allowed or not isinstance(tx.get('receipts'), list):
                raise ValueError('unexpected or malformed transaction')
            if h not in found or len(tx['receipts']) > len(found[h]['receipts']):
                found[h] = tx
    return list(found.values())


def collect_unknown(client, count, seen, attackers, signers):
    if not 0 <= count <= 1000:
        raise ValueError('unknown sample count must be between 0 and 1000')
    rows, excluded, pages = [], Counter(), []
    cursor = None
    for _ in range(10):
        if len(rows) >= count:
            break
        page = client.account_page('intents.near', desc=True, limit=200, resume_token=cursor)
        index = page.get('account_txs')
        if not isinstance(index, list):
            raise ValueError('account response has no index list')
        hashes = unique(r['transaction_hash'] for r in index)
        pages.append({'index_rows': len(index), 'unique_hashes': len(hashes),
                      'resume_token_sha256': hashlib.sha256(str(cursor).encode()).hexdigest()})
        hashes = [h for h in hashes if h not in seen]
        seen.update(hashes)
        txs = checked_transactions(client, hashes)
        excluded['missing_transactions'] += len(hashes) - len(txs)
        for tx in txs:
            why = exclusion_reason(tx, attackers, signers)
            if why:
                excluded[why] += 1
                continue
            rows.append(attach_meta(tx, 'fastnear-fresh-unlabelled', None,
                                    role='unlabelled_traffic', month=tx_month(tx),
                                    ground_truth='unknown', use='post-selection alert-rate stress test only'))
            if len(rows) == count:
                break
        next_cursor = page.get('resume_token')
        if not next_cursor or next_cursor == cursor:
            break
        cursor = next_cursor
    return rows, dict(excluded), pages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, help='Put cases and unknown traffic in a fresh directory')
    parser.add_argument('--cases-dir', type=Path, default=CASES)
    parser.add_argument('--unknown-output', type=Path, default=DATA / 'v2_fresh_unknown.jsonl.gz')
    parser.add_argument('--unknown-count', type=int, choices=range(1001), metavar='0..1000', default=500)
    args = parser.parse_args()
    if args.output_dir:
        if args.cases_dir != CASES or args.unknown_output != DATA / 'v2_fresh_unknown.jsonl.gz':
            parser.error('--output-dir cannot be combined with individual output paths')
        args.cases_dir = args.output_dir / 'cases'
        args.unknown_output = args.output_dir / 'fresh_unknown.jsonl.gz'
    manifest_path = args.cases_dir / 'manifest.json'
    if (manifest_path.exists() or args.unknown_output.exists()
            or any((args.cases_dir / (case['tx_hash'] + '.json.gz')).exists() for case in SOURCED_CASES)):
        raise SystemExit('collection output exists; choose fresh paths and preserve the previous sample')
    args.cases_dir.mkdir(parents=True, exist_ok=True)
    labels = load_labels(LABELS)
    seen = {row['tx_hash'] for row in labels}
    dedupe_sources = {str(LABELS.relative_to(ROOT)): sha(LABELS)}
    normals = DATA / 'normals.jsonl.gz'
    if normals.exists():
        seen.update(tx_hash(tx) for tx in iter_jsonl_gz(normals))
        dedupe_sources[str(normals.relative_to(ROOT))] = sha(normals)
    client = FastNear(pacer=Pacer(1.2), max_tries=2, refuse_after=15)
    manifest = {'schema_version': 1, 'started_at': now_iso(), 'network': 'mainnet',
                'collector_sha256': sha(Path(__file__)), 'source': 'https://tx.main.fastnear.com/v0',
                'dedupe_sources': dedupe_sources, 'cases': [],
                'limits': ['New sourced cases are outside the current Intents detector scope.',
                           'Two Rhea transactions belong to one attack family, not independent techniques.',
                           'Fresh traffic is unlabelled, correlated recent activity; alert rate is not false-positive rate.',
                           'Raw receipt responses are provider evidence, not independent balance-state proofs.']}
    fresh_cases = [case for case in SOURCED_CASES if case['tx_hash'] not in seen]
    found = {tx_hash(tx): tx for tx in checked_transactions(client, [c['tx_hash'] for c in fresh_cases])}
    for case in fresh_cases:
        tx = found.get(case['tx_hash'])
        if tx is None:
            manifest['cases'].append({**case, 'status': 'missing_from_provider'})
            continue
        tx = attach_meta(tx, case['source_url'], case['label'], case['campaign'], case['role'],
                         protocol=case['protocol'], intents_supported=case['intents_supported'],
                         month=tx_month(tx), use='post-selection external scope case; not training')
        path = args.cases_dir / (case['tx_hash'] + '.json.gz')
        write_records(path, [tx])
        manifest['cases'].append({**case, 'status': 'fetched', 'file': path.name, 'sha256': sha(path),
                                  'signer': tx['transaction'].get('signer_id'),
                                  'receiver': tx['transaction'].get('receiver_id'),
                                  'block_height': tx['execution_outcome'].get('block_height'),
                                  'block_timestamp': tx['execution_outcome'].get('block_timestamp'),
                                  'receipts': len(tx['receipts'])})
    attackers = attacker_ids(json.loads(ATTACKERS.read_text()))
    signers = labelled_signers(labels) | {tx['transaction']['signer_id'] for tx in found.values()}
    seen.update(found)
    fresh, exclusions, pages = collect_unknown(client, args.unknown_count, seen, attackers, signers)
    write_records(args.unknown_output, fresh)
    display_path = args.unknown_output.relative_to(ROOT) if args.unknown_output.is_relative_to(ROOT) else args.unknown_output
    manifest['unknown_sample'] = {'path': str(display_path), 'n': len(fresh),
                                  'sha256': sha(args.unknown_output), 'label': None,
                                  'ground_truth': 'unknown', 'exclusions': exclusions, 'pages': pages}
    manifest.update(completed_at=now_iso(), requests=client.stats)
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'manifest': str(manifest_path), 'cases': len(found), 'unknown': len(fresh),
                      'requests': client.stats}, indent=2))


if __name__ == '__main__':
    main()
