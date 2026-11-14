"""Train transaction candidates with accounting and strictly prior history evidence.

Research only. `prepare` caches features; `run` freezes selection before final diagnostics.
Use --output-dir for a fresh experiment. Existing completed reports cannot be overwritten.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
import gzip
import hashlib
from itertools import islice
import json
import math
from pathlib import Path
import pickle
import platform
import time

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from threadpoolctl import threadpool_limits

from near.intents import features as ft, model as md
from near.intents.collect import attacker_ids, exclusion_reason, labelled_signers, load_labels

ROOT = md.ROOT
REPORT = ROOT / 'near/intents/reports/transactions_v2.json'
CACHE = ROOT / 'near/models/transactions_v2_features.pkl'
SYNTHETIC = ROOT / 'near/data/intents/v2_synthetic'
CANDIDATES = ('extended_iforest', 'real_hgb', 'mixed_hgb', 'mixed_extra_trees')
SEED = 20261114
PROTOCOL = {
    'version': 2,
    'declared_before_fitting': True,
    'candidates': list(CANDIDATES),
    'normal_partitions': {'fit': '<=2026-05', 'calibration': '2026-06..2026-07',
                          'selection': '2026-08..2026-09', 'retrospective': '>=2026-10'},
    'contamination': 'Exclude known attacker mentions, labelled non-team signers and labelled transaction hashes from normal fitting/calibration/selection.',
    'normal_coverage': 'Normal fitting/calibration/selection use supported Intents calls with complete receipt graphs; retrospective baseline comparison retains the original collector population and reports supported/complete slices.',
    'positive_coverage': 'Real fitting and family-held-out classification use supported, complete Intents cases. Historical labelled attempts that never reach Intents are retained as separate scope records, not trained or counted as Intents detections.',
    'features': 'Frozen receipt features plus accounting and strictly earlier bounded history. No account IDs, hashes, category labels, source labels or absolute timestamps. Coverage/missing-data flags are diagnostics, not model columns. Unsupported synthetic controls are scope tests, excluded from Intents classifier fitting/accuracy.',
    'history': 'Observed records only, at most 100 prior related summaries in one day; prior receipt completion must precede target start in height and timestamp. Partial sampled history is never a complete account history.',
    'synthetic': 'Use generated train only for mixed fitting; validation for selection; test only after selection. Template/actor groups must not overlap splits. Synthetic accuracy remains separate from real-case evidence.',
    'training': 'IsolationForest: 300 trees, 2048 samples. HGB:150 iterations,learning_rate=.05,15 leaves,min_leaf=20,l2=3. ExtraTrees:300 trees,min_leaf=4,max_features=.75. Four threads, fixed seed. Real positive total weight = normal total weight; synthetic rows collectively receive at most20% of real-positive total weight.',
    'thresholds': 'June/July nominal negatives; ML-only high alert budget0.01%, medium0.1%, preserving deterministic rules separately.',
    'selection': 'Eligible if selection normal high and medium+ alerts do not exceed frozen baseline. Maximize macro real leave-family-out medium+ recall, then synthetic validation balanced accuracy, then fewer selection alerts; fixed candidate order breaks ties.',
    'family_holdout': 'Real family-held-out development comparison refits each candidate without that real family and its synthetic family. After selection, synthetic test and leave-family-out tests are diagnostic; all family designs are development-informed.',
    'final_evaluation': 'Previously examined October/November collector normals and known campaigns are retrospective. Newly fetched unknown traffic yields alert rate, never false-positive rate. Other-protocol attacks remain unsupported, not Intents positives.',
    'promotion': 'No historical collector high/medium false-alert regression; no lost real detections; added detections in independently sourced supported attack families; no synthetic domain/duplicate shortcut. No automatic production model replacement.',
    'domain_audit': 'After selection, fit a separate fixed100-tree shallow ExtraTrees domain classifier on real normal fit rows versus synthetic benign train rows; score real selection normals versus synthetic benign test. Report balanced source-classification accuracy as a domain-shift diagnostic, never attack accuracy.',
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def safe_count(labels):
    labels = np.asarray(labels)
    n = len(labels)
    return {'n': n, 'high': int((labels == 'high').sum()), 'medium_plus': int((labels != 'low').sum()),
            'medium_plus_rate': float((labels != 'low').mean()) if n else None}


def severity_labels(severity):
    return np.where(severity >= 3, 'high', np.where(severity >= 2, 'medium', 'low'))


def temporal_masks(months):
    m = np.asarray(months).astype(str)
    return {'fit': m <= '2026-05', 'calibration': (m >= '2026-06') & (m <= '2026-07'),
            'selection': (m >= '2026-08') & (m <= '2026-09'), 'retrospective': m >= '2026-10'}


def source_hashes():
    paths = ['features.py', 'model.py', 'accounting.py', 'history.py', 'taxonomy.py',
             'fixtures/attack_taxonomy.json', 'train_transactions.py']
    return {f'near/intents/{name}': md.sha256_file(ROOT / 'near/intents' / name)
            for name in paths if (ROOT / 'near/intents' / name).exists()}


def rows_from(path):
    opener = gzip.open if str(path).endswith('.gz') else open
    with opener(path, 'rt') as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def max_severity(findings):
    return max(({'high': 3, 'medium': 2, 'low': 1}.get(f.get('severity'), 0)
                for f in findings), default=0)


def attack_family(meta):
    from near.intents.taxonomy import family_for_campaign
    for key in ('family', 'category', 'attack_family', 'campaign'):
        if found := family_for_campaign(meta.get(key)):
            return found
    if meta.get('family') == 'benign_failure':
        return 'benign_failure'
    campaign = meta.get('campaign', '') or ''
    for prefix, family in [('2026-10-01', 'callback_accounting'), ('2026-04-03', 'resource_exhaustion'),
                           ('2026-05-20', 'token_spoofing'), ('2026-05-23', 'access_control')]:
        if campaign.startswith(prefix):
            return family
    return 'unclassified'


def check_synthetic_splits(records):
    """Identities/templates are grouping metadata, never predictors."""
    owners = {}
    for r in records:
        if r['source_kind'] != 'synthetic':
            continue
        for key in ('template_id', 'actor_group'):
            value = r.get(key)
            if not value:
                raise ValueError(f'synthetic record lacks {key}')
            tag = (key, value)
            if tag in owners and owners[tag] != r['partition']:
                raise ValueError(f'synthetic {key} overlaps partitions: {value}')
            owners[tag] = r['partition']


def candidate_scores(model, X):
    if model['kind'] == 'extended_iforest':
        return model['estimator'].score(X)
    return model['estimator'].predict_proba(X)[:, 1]


def fit_candidate(kind, Xnormal, Xreal, Xsynthetic, ysynthetic):
    if kind == 'extended_iforest':
        estimator = md.IForestModel(n_estimators=300, max_samples=2048, seed=SEED)
        estimator.params['n_jobs'] = 4
        return {'kind': kind, 'estimator': estimator.fit(Xnormal)}
    if not len(Xreal):
        raise ValueError('supervised fit needs real positive families')
    parts = [Xnormal, Xreal]
    targets = [np.zeros(len(Xnormal), int), np.ones(len(Xreal), int)]
    weights = [np.ones(len(Xnormal)), np.full(len(Xreal), len(Xnormal) / len(Xreal))]
    if kind.startswith('mixed') and len(Xsynthetic):
        parts.append(Xsynthetic); targets.append(ysynthetic)
        weights.append(np.full(len(Xsynthetic), .2 * len(Xnormal) / len(Xsynthetic)))
    if kind == 'mixed_extra_trees':
        estimator = ExtraTreesClassifier(n_estimators=300, min_samples_leaf=4, max_features=.75,
                                         random_state=SEED, n_jobs=4)
    else:
        estimator = HistGradientBoostingClassifier(max_iter=150, learning_rate=.05, max_leaf_nodes=15,
                    min_samples_leaf=20, l2_regularization=3., early_stopping=False, random_state=SEED)
    estimator.fit(np.concatenate(parts), np.concatenate(targets), sample_weight=np.concatenate(weights))
    return {'kind': kind, 'estimator': estimator}


def calibrate(scores):
    forced = np.zeros(len(scores), bool)
    high = md.alert_threshold(scores, forced, md.HIGH_RATE)
    return {'high': high, 'medium': min(high, md.alert_threshold(scores, forced, md.MEDIUM_RATE))}


def combined_labels(severity, scores, thresholds):
    return md.labels_for(severity, scores, thresholds)


def selection_key(candidate, order):
    return (-candidate['real_family_macro_recall'], -candidate['synthetic_validation_balanced_accuracy'],
            candidate['selection_normals']['medium_plus'], order)


def select_candidate(candidates, baseline):
    eligible = [name for name, c in candidates.items()
                if c['selection_normals']['high'] <= baseline['high']
                and c['selection_normals']['medium_plus'] <= baseline['medium_plus']]
    return min(eligible, key=lambda name: selection_key(candidates[name], CANDIDATES.index(name))) if eligible else None


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')


def extract_features(synthetic_dir, cache_path):
    """One raw-data pass, followed by a chronological join of compact summaries."""
    from near.intents import accounting as ac, history as hi
    paths = {'normal': md.NORMALS, 'real': md.LABELLED}
    paths.update({f'synthetic:{part}': synthetic_dir / f'{part}.jsonl.gz'
                  for part in ('train', 'validation', 'test') if (synthetic_dir / f'{part}.jsonl.gz').exists()})
    inputs = {key: md.sha256_file(path) for key, path in paths.items()}
    code = source_hashes()
    if cache_path.exists():
        with open(cache_path, 'rb') as stream:
            cached = pickle.load(stream)
        if cached['inputs'] == inputs and cached['code_sha256'] == code:
            return cached
        print('Rebuilding features from source/data-keyed parts; prior parts remain local.', flush=True)
    old = md.load_cache()
    if old['normals_sha256'] != inputs['normal'] or old['labelled_sha256'] != inputs['real']:
        raise ValueError('frozen feature cache does not match raw data')
    indexed = {name: {str(h): i for i, h in enumerate(old[name]['ids'])} for name in ('normals', 'labelled')}
    attackers = attacker_ids(json.loads((ROOT / 'near/intents/fixtures/attacker_accounts.json').read_text()))
    signers = labelled_signers(load_labels(ROOT / 'near/data/intents/all_labelled_txs.jsonl'))
    labelled_ids = set(indexed['labelled'])
    records, summaries, base, accounting, a_severity = [], [], [], [], []
    for kind, path in paths.items():
        part_path = cache_path.parent / 'transactions_v2_parts' / f"{kind.replace(':', '_')}-{digest({'input': inputs[kind], 'code': code})[:16]}.pkl"
        if part_path.exists():
            with open(part_path, 'rb') as stream:
                saved = pickle.load(stream)
            for target, key in [(records, 'records'), (summaries, 'summaries'), (base, 'base'),
                                (accounting, 'accounting'), (a_severity, 'accounting_severity')]:
                target.extend(saved[key])
            print(f'cached {kind}: {len(saved["records"])}', flush=True)
            continue
        first = len(records)
        count = 0
        for tx in rows_from(path):
            meta = tx.get('_meta') or {}
            tx_id = tx['transaction']['hash']
            summary = hi.summarize_transaction(tx)
            evidence = ac.analyze_accounting(tx)
            av = ac.accounting_features(tx)
            old_name = {'normal': 'normals', 'real': 'labelled'}.get(kind)
            if old_name:
                n = indexed[old_name][tx_id]
                bx, sev, flow, failed = (old[old_name][k][n] for k in ('X', 'rule_sev', 'flow', 'failed'))
            else:
                features = ft.tx_features(tx)
                bx = [features[k] for k in ft.FEATURE_KEYS]
                sev = max_severity(ft.rule_hits(tx))
                flow, failed = ft.flow_type(tx), features['n_failed'] > 0
            excluded = ('labelled_hash' if tx_id in labelled_ids else exclusion_reason(tx, attackers, signers)) if kind == 'normal' else None
            records.append({'id': tx_id, 'source_kind': 'synthetic' if kind.startswith('synthetic:') else kind,
                            'partition': kind.split(':')[1] if ':' in kind else None,
                            'month': meta.get('month') or '', 'source': meta.get('source'),
                            'label': meta.get('label'), 'role': meta.get('role'), 'family': attack_family(meta),
                            'excluded': excluded, 'template_id': meta.get('template_id'),
                            'actor_group': meta.get('actor_group'), 'observable': meta.get('observable', True),
                            'supported': bool(summary.get('protocols')),
                            'sandbox_run_id': meta.get('sandbox_run_id'),
                            'flow': str(flow), 'failed': bool(failed), 'rule_severity': int(sev),
                            'accounting_status': evidence.get('status'), 'history_complete': summary.get('complete', False)})
            base.append(bx); accounting.append([av[k] for k in ac.ACCOUNTING_FEATURE_KEYS])
            a_severity.append(max_severity(evidence.get('findings', [])))
            summaries.append(summary)
            count += 1
            if count % 10000 == 0:
                print(f'extracted {kind}: {count}', flush=True)
        print(f'extracted {kind}: {count} total', flush=True)
        part_path.parent.mkdir(parents=True, exist_ok=True)
        with open(part_path, 'wb') as stream:
            pickle.dump({'records': records[first:], 'summaries': summaries[first:], 'base': base[first:],
                         'accounting': accounting[first:], 'accounting_severity': a_severity[first:]}, stream,
                        protocol=pickle.HIGHEST_PROTOCOL)
    check_synthetic_splits(records)
    ids = [r['id'] for r in records]
    # Real/normal duplicates are excluded from fitting rather than allowed to create self-history.
    hist, h_severity = np.zeros((len(records), len(hi.HISTORY_FEATURE_KEYS))), np.zeros(len(records), int)
    by_actor = defaultdict(lambda: deque(maxlen=hi.MAX_HISTORY_TRANSACTIONS))
    ordered = sorted(range(len(records)), key=lambda i: (summaries[i].get('start_height') or 0,
                                                        summaries[i].get('start_timestamp') or 0, ids[i]))
    seen = set()
    for i in ordered:
        s = summaries[i]
        # Synthetic partitions are separate worlds; their actors never supply real context.
        domain = f"sandbox:{records[i]['partition']}:{records[i]['sandbox_run_id']}" if records[i]['source_kind'] == 'synthetic' else 'mainnet'
        prior_ids = {j for actor in s['participants'] for j in by_actor[(domain, actor)]}
        prior_ids = sorted(prior_ids, key=lambda j: summaries[j].get('start_height') or 0, reverse=True)[:hi.MAX_HISTORY_TRANSACTIONS]
        priors = [summaries[j] for j in prior_ids]
        hf = hi.history_features_from_summaries(s, priors)
        he = hi.analyze_history_summaries(s, priors)
        hist[i] = [hf[k] for k in hi.HISTORY_FEATURE_KEYS]
        h_severity[i] = max_severity(he.get('findings', []))
        if (domain, ids[i]) not in seen:
            for actor in s['participants']:
                by_actor[(domain, actor)].append(i)
            seen.add((domain, ids[i]))
    omitted = {'accounting_complete', 'accounting_unchecked_flows_log', 'accounting_malformed_events_log',
               'history_available', 'history_related_log', 'history_seconds_since_previous_log'}
    all_keys = list(ft.FEATURE_KEYS) + list(ac.ACCOUNTING_FEATURE_KEYS) + list(hi.HISTORY_FEATURE_KEYS)
    all_x = np.hstack((np.array(base), np.array(accounting), hist)).astype(np.float32)
    keep = [i for i, k in enumerate(all_keys) if k not in omitted]
    cache = {'inputs': inputs, 'code_sha256': code, 'records': records, 'X': all_x[:, keep],
             'base_X': np.array(base, np.float32), 'feature_keys': [all_keys[i] for i in keep],
             'accounting_severity': np.array(a_severity), 'history_severity': h_severity,
             'history_features': hist, 'history_keys': list(hi.HISTORY_FEATURE_KEYS)}
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, 'wb') as stream:
        pickle.dump(cache, stream, protocol=pickle.HIGHEST_PROTOCOL)
    cache_path.with_suffix('.json').write_text(json.dumps({'sha256': md.sha256_file(cache_path),
        'code_sha256': code, 'inputs': inputs, 'note': 'Trusted local feature cache. Cache-only reproduction does not independently reconstruct raw receipts.'}, indent=2) + '\n')
    return cache


def synthetic_metrics(labels, rows):
    out = {}
    for family in sorted({r['family'] for r in rows}):
        sel = np.array([r['family'] == family for r in rows])
        positive = np.array([r['label'] == 1 for r in rows]) & sel
        negative = np.array([r['label'] == 0 for r in rows]) & sel
        p, n = safe_count(labels[positive]), safe_count(labels[negative])
        balanced = (p['medium_plus_rate'] + 1 - n['medium_plus_rate']) / 2 if p['n'] and n['n'] else None
        out[family] = {'positive': p, 'benign': n, 'balanced_accuracy': balanced,
                       'specificity': 1 - n['medium_plus_rate'] if n['n'] else None,
                       'actor_groups': len({r['actor_group'] for r in rows if r['family'] == family})}
    return out


def feature_overlap(X, records):
    fingerprints = defaultdict(set)
    for x, r in zip(X, records):
        if r['source_kind'] == 'synthetic':
            fingerprints[r['partition']].add(hashlib.sha256(x.tobytes()).hexdigest())
    return {f'{a}_{b}': len(fingerprints[a] & fingerprints[b])
            for a, b in [('train', 'validation'), ('train', 'test'), ('validation', 'test')]}


def train_and_evaluate(data, report, report_path, artifact_path):
    X, rows = data['X'], data['records']
    source = np.array([r['source_kind'] for r in rows])
    family = np.array([r['family'] for r in rows])
    label = np.array([r['label'] for r in rows], object)
    partition = np.array([r['partition'] for r in rows], object)
    normal = (source == 'normal') & np.array([r['excluded'] is None for r in rows])
    masks = temporal_masks([r['month'] for r in rows])
    masks = {k: mask & normal for k, mask in masks.items()}
    supported_complete = np.array([r['supported'] and r['history_complete'] for r in rows])
    for part in ('fit', 'calibration', 'selection'):
        masks[part] &= supported_complete
    all_real = (source == 'real') & (label == 1)
    real = all_real & supported_complete
    syn = (source == 'synthetic') & np.array([r['observable'] and r['supported'] for r in rows])
    syn_fit, syn_val, syn_test = (syn & (partition == p) for p in ('train', 'validation', 'test'))
    rule_sev = np.array([r['rule_severity'] for r in rows])
    evidence_sev = np.maximum.reduce((rule_sev, data['accounting_severity'], data['history_severity']))
    flows = np.array([r['flow'] for r in rows])
    baseline = md.load_artifact()
    baseline_scores = md.score_matrix(baseline, data['base_X'], flows)
    baseline_labels = md.labels_for(rule_sev, baseline_scores, baseline['thresholds'])
    deterministic_labels = severity_labels(evidence_sev)
    report.update(status='fitting', run_trainer_sha256=md.sha256_file(__file__),
                  inputs=data['inputs'], feature_code_sha256=data['code_sha256'], feature_keys=data['feature_keys'],
                  split_counts={k: int(v.sum()) for k, v in masks.items()},
                  split_id_hashes={k: digest(sorted(rows[i]['id'] for i in np.flatnonzero(v))) for k, v in masks.items()},
                  normal_exclusions=dict(Counter(r['excluded'] for r in rows if r['excluded'])),
                  real_case_coverage={'all_labelled_positives': int(all_real.sum()), 'supported_complete': int(real.sum()),
                      'outside_classification_scope': [{'id': rows[i]['id'], 'family': rows[i]['family'],
                          'supported': rows[i]['supported'], 'complete': rows[i]['history_complete']}
                          for i in np.flatnonzero(all_real & ~supported_complete)]},
                  synthetic_counts={p: int((syn & (partition == p)).sum()) for p in ('train', 'validation', 'test')},
                  synthetic_unsupported_controls=int(((source == 'synthetic') & ~np.array([r['supported'] for r in rows])).sum()),
                  synthetic_feature_vector_overlap=feature_overlap(X, rows),
                  runtime={'python': platform.python_version(), 'numpy': np.__version__})
    write_report(report_path, report)
    fitted, thresholds, candidates, family_predictions = {}, {}, {}, {}
    real_families = sorted(set(family[real]))
    Xnormal = X[masks['fit']]
    with threadpool_limits(4):
        for name in CANDIDATES:
            tick = time.monotonic()
            model = fit_candidate(name, Xnormal, X[real], X[syn_fit], label[syn_fit].astype(int))
            fitted[name] = model
            thresholds[name] = calibrate(candidate_scores(model, X[masks['calibration']]))
            selection_labels = combined_labels(evidence_sev[masks['selection']], candidate_scores(model, X[masks['selection']]), thresholds[name])
            validation_labels = combined_labels(evidence_sev[syn_val], candidate_scores(model, X[syn_val]), thresholds[name])
            validation = synthetic_metrics(validation_labels, [r for r, keep in zip(rows, syn_val) if keep])
            held_out = {}
            family_predictions[name] = []
            for held in real_families:
                train_real = real & (family != held)
                train_syn = syn_fit & (family != held)
                test_real = real & (family == held)
                m = model if name == 'extended_iforest' else fit_candidate(name, Xnormal, X[train_real], X[train_syn], label[train_syn].astype(int))
                thr = calibrate(candidate_scores(m, X[masks['calibration']]))
                pred = combined_labels(evidence_sev[test_real], candidate_scores(m, X[test_real]), thr)
                held_out[held] = safe_count(pred)
                held_out[held]['deterministic'] = safe_count(deterministic_labels[test_real])
                family_predictions[name].extend({'id': rows[i]['id'], 'family': held, 'label': str(lab),
                    'baseline': str(baseline_labels[i]), 'deterministic': str(deterministic_labels[i])}
                    for i, lab in zip(np.flatnonzero(test_real), pred))
            candidates[name] = {'selection_normals': safe_count(selection_labels),
                'real_leave_family_out': held_out,
                'real_family_macro_recall': float(np.mean([x['medium_plus_rate'] for x in held_out.values()])),
                'synthetic_validation': validation,
                'synthetic_validation_balanced_accuracy': float(np.mean([x['balanced_accuracy'] for x in validation.values() if x['balanced_accuracy'] is not None])),
                'thresholds': thresholds[name], 'fit_and_development_seconds': round(time.monotonic() - tick, 2)}
            print(name, json.dumps(candidates[name]), flush=True)
        selected = select_candidate(candidates, safe_count(baseline_labels[masks['selection']]))
        # If every candidate violates the normal-alert budget, preserve the failed comparison without deployment.
        artifact_name = selected or CANDIDATES[0]
        report.update(status='selection_frozen', selected=selected, artifact_candidate=artifact_name,
                      selected_at=md.utc_now(), candidates=candidates,
                      real_family_holdout_predictions=family_predictions,
                      selection_baseline=safe_count(baseline_labels[masks['selection']]))
        write_report(report_path, report)
        model, thr = fitted[artifact_name], thresholds[artifact_name]
        scores = candidate_scores(model, X)
        candidate_labels = combined_labels(evidence_sev, scores, thr)
        systems = {'baseline': baseline_labels, 'deterministic': deterministic_labels, 'candidate': candidate_labels,
                   'learned_only': combined_labels(np.zeros(len(rows), int), scores, thr)}
        collector = masks['retrospective'] & np.array([not str(r['source']).startswith('fastnear-seed') for r in rows])
        report['retrospective_normals'] = {name: {'collector': safe_count(labs[collector]),
             'collector_supported_complete': safe_count(labs[collector & supported_complete]),
             'collector_failed': safe_count(labs[collector & np.array([r['failed'] for r in rows])]),
             'all': safe_count(labs[masks['retrospective']])} for name, labs in systems.items()}
        report['in_sample_known_real_cases'] = {name: {f: safe_count(labs[real & (family == f)]) for f in real_families}
                                    for name, labs in systems.items()}
        report['learned_contribution'] = {
            'in_sample_real_additional_medium_plus': int((real & (deterministic_labels == 'low') & (candidate_labels != 'low')).sum()),
            'retrospective_collector_additional_medium_plus': int((collector & (deterministic_labels == 'low') & (candidate_labels != 'low')).sum()),
            'note': 'Full-fit real cases are in-sample. Use family-held-out development counts for generalization diagnostics.'}
        report['synthetic_test'] = {name: synthetic_metrics(labs[syn_test], [r for r, keep in zip(rows, syn_test) if keep])
                                    for name, labs in systems.items()}
        holdout = {}
        for held in sorted(set(family[syn_test])):
            train_real = real & (family != held); train_syn = syn_fit & (family != held)
            test_syn = syn_test & (family == held)
            m = model if artifact_name == 'extended_iforest' else fit_candidate(artifact_name, Xnormal, X[train_real], X[train_syn], label[train_syn].astype(int))
            hthr = calibrate(candidate_scores(m, X[masks['calibration']]))
            pred = combined_labels(evidence_sev[test_syn], candidate_scores(m, X[test_syn]), hthr)
            holdout[held] = synthetic_metrics(pred, [r for r, keep in zip(rows, test_syn) if keep])[held]
        report['synthetic_leave_family_out_test'] = holdout
        report['domain_audit'] = domain_audit(X, masks['fit'], masks['selection'], syn_fit & (label == 0), syn_test & (label == 0))
    prediction_path = artifact_path.with_suffix('.predictions.npz')
    prediction_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(prediction_path, ids=np.array([r['id'] for r in rows]), scores=scores,
                        **{name: labels for name, labels in systems.items()})
    report['prediction_audit'] = {'path': str(prediction_path), 'sha256': md.sha256_file(prediction_path)}
    fit_mask = masks['fit'].copy()
    if artifact_name != 'extended_iforest':
        fit_mask |= real
    if artifact_name.startswith('mixed'):
        fit_mask |= syn_fit
    artifact = {'version': 'transactions_v2_research', 'model': model, 'thresholds': thr,
                'feature_keys': data['feature_keys'], 'feature_code_sha256': data['code_sha256'],
                'inference_code_sha256': md.sha256_file(__file__),
                'protocol_sha256': digest(PROTOCOL), 'research_only': True,
                'fit_ids_sha256': digest(sorted(rows[i]['id'] for i in np.flatnonzero(fit_mask))),
                'fit_rows_by_source': dict(Counter(source[fit_mask].tolist()))}
    report['artifact_fit_rows_by_source'] = artifact['fit_rows_by_source']
    report['artifact_fit_ids_sha256'] = artifact['fit_ids_sha256']
    report['external_evaluation'] = evaluate_external(artifact)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(pickle.dumps(artifact, protocol=pickle.HIGHEST_PROTOCOL))
    report['artifact'] = {'path': str(artifact_path), 'sha256': md.sha256_file(artifact_path),
                          'bytes': artifact_path.stat().st_size}
    artifact_path.with_suffix('.json').write_text(json.dumps({**report['artifact'],
        'version': artifact['version'], 'research_only': True, 'feature_code_sha256': data['code_sha256'],
        'inference_code_sha256': artifact['inference_code_sha256'], 'protocol_sha256': digest(PROTOCOL)}, indent=2) + '\n')
    report['adoption'] = {'deployed': False, 'recommendation': 'research_only_pending_independent_supported_attack_cases',
        'reason': 'No newly sourced independent Intents-positive family is available; all supported attacks informed development. Synthetic success and unknown-traffic alert rates cannot establish real-world accuracy.'}
    report['history_coverage'] = {name: {'n': int(mask.sum()), 'with_prior_evidence': int((data['history_features'][mask, 0] > 0).sum())}
                                  for name, mask in {**masks, 'real': real, 'synthetic': syn}.items()}
    report.update(status='complete', completed_at=md.utc_now())
    write_report(report_path, report)
    return artifact


def evaluate_external(artifact):
    """Reserved post-selection traffic/cases. Unknown activity has no accuracy label."""
    from near.intents import history as hi
    fresh_path = ROOT / 'near/data/intents/v2_fresh_unknown.jsonl.gz'
    result = {'fresh_unknown': {'status': 'not_available'}}
    if fresh_path.exists():
        txs = list(rows_from(fresh_path))
        if any((tx.get('_meta') or {}).get('label') is not None for tx in txs):
            raise ValueError('fresh unknown traffic unexpectedly contains ground-truth labels')
        summaries = [hi.summarize_transaction(tx) for tx in txs]
        order = sorted(range(len(txs)), key=lambda i: (summaries[i].get('start_height') or 0,
                                                      summaries[i].get('start_timestamp') or 0))
        prior_by_actor = defaultdict(lambda: deque(maxlen=hi.MAX_HISTORY_TRANSACTIONS))
        records = []
        with threadpool_limits(4):
            for i in order:
                s = summaries[i]
                prior = {j for actor in s['participants'] for j in prior_by_actor[actor]}
                prior = sorted(prior, key=lambda j: summaries[j].get('start_height') or 0, reverse=True)[:hi.MAX_HISTORY_TRANSACTIONS]
                candidate = score_candidate(txs[i], [txs[j] for j in prior], artifact)
                baseline = md.score_tx(txs[i])
                deterministic = severity_labels(np.array([max(max_severity(candidate['rule_hits']),
                    max_severity(candidate['accounting'].get('findings', [])), max_severity(candidate['history'].get('findings', [])))]))[0]
                records.append({'id': s['tx_hash'], 'baseline': baseline['label'], 'candidate': candidate['label'],
                                'deterministic': str(deterministic), 'supported': candidate['supported'],
                                'complete': bool(s['complete'])})
                for actor in s['participants']:
                    prior_by_actor[actor].append(i)
        result['fresh_unknown'] = {'status': 'complete', 'sha256': md.sha256_file(fresh_path),
            'ground_truth': 'unknown; these are alert rates, not false-positive rates or accuracy',
            'n': len(records), 'complete': sum(r['complete'] for r in records),
            'systems': {name: safe_count(np.array([r[name] for r in records])) for name in ('baseline', 'deterministic', 'candidate')},
            'predictions': records}
    manifest_path = ROOT / 'near/intents/fixtures/cases_v2/manifest.json'
    if manifest_path.exists():
        cases = []
        for path in sorted(manifest_path.parent.glob('*.json.gz')):
            tx = next(rows_from(path)); summary = hi.summarize_transaction(tx)
            cases.append({'id': tx['transaction']['hash'], 'sha256': md.sha256_file(path),
                          'supported': bool(summary.get('protocols')), 'declared_protocol': tx.get('_meta', {}).get('protocol'),
                          'use': 'external scope check only; not a new Intents accuracy observation'})
        result['external_attack_cases'] = {'manifest_sha256': md.sha256_file(manifest_path), 'cases': cases}
    return result


def domain_audit(X, fit_normal, test_normal, fit_generated, test_generated):
    """Can a classifier tell generated benign cases from real nominal traffic?"""
    rng = np.random.RandomState(SEED)
    def capped(mask):
        ids = np.flatnonzero(mask)
        return rng.choice(ids, min(1000, len(ids)), replace=False)
    a, b, c, d = (capped(mask) for mask in (fit_normal, fit_generated, test_normal, test_generated))
    if not len(b) or not len(d):
        return {'status': 'unavailable', 'reason': 'No supported generated benign records'}
    clf = ExtraTreesClassifier(n_estimators=100, max_depth=6, min_samples_leaf=2,
                               class_weight='balanced', random_state=SEED, n_jobs=4)
    clf.fit(X[np.r_[a, b]], np.r_[np.zeros(len(a)), np.ones(len(b))])
    real_correct = float((clf.predict(X[c]) == 0).mean())
    generated_correct = float((clf.predict(X[d]) == 1).mean())
    return {'status': 'complete', 'fit_real': len(a), 'fit_generated': len(b), 'test_real': len(c),
            'test_generated': len(d), 'real_correct_rate': real_correct, 'generated_correct_rate': generated_correct,
            'balanced_domain_accuracy': (real_correct + generated_correct) / 2,
            'interpretation': 'Source separability, not attack accuracy. Shared generator/WASM and unmatched benign operations can create shortcuts.'}


def load_candidate(path):
    """Load only a trusted local research artifact after digest/source validation."""
    path = Path(path)
    manifest = json.loads(path.with_suffix('.json').read_text())
    if md.sha256_file(path) != manifest['sha256']:
        raise ValueError('candidate artifact hash mismatch')
    for source, expected in manifest['feature_code_sha256'].items():
        if md.sha256_file(ROOT / source) != expected:
            raise ValueError(f'candidate feature source changed: {source}')
    if manifest['inference_code_sha256'] != md.sha256_file(__file__):
        raise ValueError('candidate inference source changed')
    with open(path, 'rb') as stream:
        return pickle.load(stream)


def load_feature_cache(path):
    """Validate a trusted distributed matrix before reading the pickle payload."""
    path = Path(path)
    manifest = json.loads(path.with_suffix('.json').read_text())
    if md.sha256_file(path) != manifest['sha256']:
        raise ValueError('feature cache hash mismatch')
    if manifest['code_sha256'] != source_hashes():
        raise ValueError('feature cache source hash mismatch')
    with open(path, 'rb') as stream:
        data = pickle.load(stream)
    if data['inputs'] != manifest['inputs'] or data['code_sha256'] != manifest['code_sha256']:
        raise ValueError('feature cache manifest mismatch')
    return data


def score_candidate(tx, prior_txs, artifact):
    """Experimental inference; caller supplies trusted local artifact and bounded raw history."""
    from near.intents import accounting as ac, history as hi
    prior_txs = list(islice(prior_txs, hi.MAX_HISTORY_TRANSACTIONS))
    for path, expected in artifact['feature_code_sha256'].items():
        if md.sha256_file(ROOT / path) != expected:
            raise ValueError(f'candidate feature source changed: {path}')
    features = {**ft.tx_features(tx), **ac.accounting_features(tx), **hi.history_features(tx, prior_txs)}
    X = np.array([[features[key] for key in artifact['feature_keys']]], np.float32)
    accounting, history = ac.analyze_accounting(tx), hi.analyze_history(tx, prior_txs)
    rules = ft.rule_hits(tx)
    severity = max(max_severity(rules), max_severity(accounting.get('findings', [])), max_severity(history.get('findings', [])))
    score = float(candidate_scores(artifact['model'], X)[0])
    return {'research_only': True, 'model_version': artifact['version'], 'score': score,
            'label': str(combined_labels(np.array([severity]), np.array([score]), artifact['thresholds'])[0]),
            'supported': bool(hi.summarize_transaction(tx).get('protocols')),
            'score_meaning': 'Uncalibrated model output, not attack probability; unsupported or incomplete data cannot establish safety.',
            'accounting': accounting, 'history': history, 'rule_hits': rules}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'run', 'score'))
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--synthetic-dir', type=Path, default=SYNTHETIC)
    parser.add_argument('--feature-cache', type=Path, help='Trusted hash-pinned distributed feature matrix; skips raw extraction')
    parser.add_argument('--artifact', type=Path, default=ROOT / 'near/models/transactions_v2_research.pkl')
    parser.add_argument('--transaction', type=Path, help='One trusted local transaction JSON/JSON.gz')
    parser.add_argument('--history', type=Path, help='Optional recorded history JSONL/JSONL.gz')
    args = parser.parse_args()
    if args.command == 'score':
        if not args.transaction:
            parser.error('score requires --transaction')
        tx = next(rows_from(args.transaction))
        prior = rows_from(args.history) if args.history else []
        print(json.dumps(score_candidate(tx, prior, load_candidate(args.artifact)), indent=2))
        return
    report_path = args.output_dir / REPORT.name if args.output_dir else REPORT
    if report_path.exists():
        report = json.loads(report_path.read_text())
        if report['status'] not in ('protocol_declared', 'features_prepared') or report['protocol_sha256'] != digest(PROTOCOL):
            raise SystemExit('fitting/evaluation already started or protocol differs; use a fresh --output-dir')
    else:
        report = {'status': 'protocol_declared', 'declared_at': md.utc_now(), 'protocol': PROTOCOL,
                  'protocol_sha256': digest(PROTOCOL)}
        write_report(report_path, report)
    cache_path = args.feature_cache or (args.output_dir / CACHE.name if args.output_dir else CACHE)
    if args.command == 'run' and not args.feature_cache and any(not (args.synthetic_dir / f'{p}.jsonl.gz').exists() for p in ('train', 'validation', 'test')):
        raise SystemExit('all three generated partitions are required before fitting')
    data = load_feature_cache(cache_path) if args.feature_cache else extract_features(args.synthetic_dir, cache_path)
    if args.command == 'run' and any(f'synthetic:{p}' not in data['inputs'] for p in ('train', 'validation', 'test')):
        raise SystemExit('feature matrix lacks a generated partition')
    report['feature_cache_sha256'] = md.sha256_file(cache_path)
    if args.command == 'prepare':
        report.update(status='features_prepared', feature_cache_sha256=md.sha256_file(cache_path),
                      feature_code_sha256=data['code_sha256'], inputs=data['inputs'])
        write_report(report_path, report)
        return
    artifact_path = (args.output_dir or ROOT / 'near/models') / 'transactions_v2_research.pkl'
    train_and_evaluate(data, report, report_path, artifact_path)


if __name__ == '__main__':
    main()
