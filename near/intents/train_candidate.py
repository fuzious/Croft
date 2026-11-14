"""Bounded local Intents training experiment; never overwrites the deployed detector.

Run: uv run python -m near.intents.train_candidate
The fixed protocol is written to the report before fitting. October/November and
campaigns are read for scoring only after selection, and are not new sealed tests.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
from threadpoolctl import threadpool_limits

from near.intents import features as ft, model as md
from near.intents.evaluate import campaign_key

REPORT = Path(__file__).parent / 'reports/training_candidate.json'
TAG = 'intents_candidate'
CANDIDATES = ('global', 'per_flow', 'per_flow_outcome')
PROTOCOL = {
    'candidate_list': list(CANDIDATES),
    'fit': 'normal transactions through 2026-05; no labelled campaigns',
    'threshold_calibration': '2026-06 and 2026-07 normals; preserve rule alerts, same high/medium rate budgets',
    'selection': '2026-08 and 2026-09 normals: fewest high alerts, then medium+ alerts, then failed-normal medium+ alerts, then simpler model',
    'eligibility': 'nonconstant train scores; finite calibrated thresholds below score ceiling 1',
    'forests': {'trees': 300, 'max_samples': 2048, 'seed': 0, 'threads': 4, 'minimum_group_rows': 256},
    'after_selection_only': 'October/November normals and labelled campaigns; retrospective development comparison, not unseen-attack accuracy',
    'adoption_gate': 'Lower clean collector retrospective medium+ false alarms, no additional high false alarms, and no lost campaign detections; root review required. Improved unseen-attack detection is not established.',
}


class ConditionalForest:
    """Raw isolation scores, with sparse/unknown groups falling back to the broader model."""
    def __init__(self, mode='global', trees=300, min_rows=256):
        self.mode, self.trees, self.min_rows = mode, trees, min_rows
        self.models = {}
        self.group_rows = {}
        self.fail_column = ft.FEATURE_KEYS.index('n_failed')

    def groups(self, X, flows):
        flow = np.asarray(flows).astype(str)
        if self.mode == 'per_flow_outcome':
            return np.char.add(np.char.add(flow, ':'), (X[:, self.fail_column] > 0).astype(int).astype(str))
        return flow

    def fit(self, X, flows):
        def add(key, mask):
            forest = md.IForestModel(n_estimators=self.trees)
            forest.params['n_jobs'] = 4
            self.models[key] = forest.fit(X[mask])
            self.group_rows[key] = int(mask.sum())
        add('*', np.ones(len(X), dtype=bool))
        if self.mode != 'global':
            for f in sorted(set(flows)):
                mask = flows == f
                if mask.sum() >= self.min_rows:
                    add(str(f), mask)
        if self.mode == 'per_flow_outcome':
            groups = self.groups(X, flows)
            for group in sorted(set(groups)):
                mask = groups == group
                if mask.sum() >= self.min_rows:
                    add(str(group), mask)
        return self

    def score(self, X, flows):
        out = np.empty(len(X), dtype=float)
        if not len(X):
            return out
        groups = self.groups(X, flows)
        for group in sorted(set(groups)):
            mask = groups == group
            flow = str(flows[np.flatnonzero(mask)[0]])
            forest = self.models.get(str(group), self.models.get(flow, self.models['*']))
            out[mask] = forest.score(X[mask])
        return out


def split(months):
    months = np.asarray(months).astype(str)
    return {'fit': months <= '2026-05', 'calibrate': (months >= '2026-06') & (months <= '2026-07'),
            'select': (months >= '2026-08') & (months <= '2026-09'), 'retrospective': months >= '2026-10'}


def counts(labels):
    return {'n': len(labels), 'high': int((labels == 'high').sum()),
            'medium_plus': int((labels != 'low').sum()), 'low': int((labels == 'low').sum())}


def selection_key(metrics, index):
    return (metrics['selection']['high'], metrics['selection']['medium_plus'],
            metrics['selection_failed']['medium_plus'], index)


def main(output_dir: Path | None = None):
    artifact_dir = md.OUT if output_dir is None else output_dir.resolve()
    report_path = REPORT if output_dir is None else artifact_dir / 'training_candidate.json'
    if report_path.exists():
        raise SystemExit(f'{report_path} already exists; preserve the experiment rather than silently rerunning it')
    report_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    report = {'status': 'protocol_written_before_fit', 'started_at': md.utc_now(), 'protocol': PROTOCOL,
              'script_sha256': md.sha256_file(__file__), 'baseline_sha256': md.sha256_file(md.OUT/'intents_v1.pkl')}
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    cache = md.load_cache()
    for source, expected in ((md.NORMALS, cache['normals_sha256']), (md.LABELLED, cache['labelled_sha256'])):
        if md.sha256_file(source) != expected:
            raise ValueError(f'Raw data changed since feature cache was built: {source}')
    report['data_hashes'] = {'cache': md.sha256_file(md.CACHE), 'normals': cache['normals_sha256'],
                             'labelled': cache['labelled_sha256']}
    normals = cache['normals']; masks = split(normals['month'])
    if len(set(normals['ids'])) != len(normals['ids']):
        raise ValueError('duplicate normal transaction IDs')
    report['split_counts'] = {name: int(mask.sum()) for name, mask in masks.items()}
    report['split_id_hashes'] = {name: md.sha256_json(sorted(normals['ids'][mask].tolist())) for name, mask in masks.items()}
    report['candidates'] = {}; fitted = {}
    train, cal, valid = (masks[k] for k in ('fit', 'calibrate', 'select'))
    X, flows, severity = normals['X'], normals['flow'].astype(str), normals['rule_sev']
    with threadpool_limits(limits=4):
        for name in CANDIDATES:
            t0 = time.monotonic()
            forest = ConditionalForest(name).fit(X[train], flows[train])
            train_scores = forest.score(X[train], flows[train])
            cal_scores = forest.score(X[cal], flows[cal])
            thr = md.calibrate(cal_scores, severity[cal])
            val_scores = forest.score(X[valid], flows[valid])
            labs = md.labels_for(severity[valid], val_scores, thr['combined'])
            eligible = bool(np.ptp(train_scores) > 0 and all(np.isfinite(t) and t < 1 for t in thr['combined'].values()))
            metrics = {'eligible': eligible, 'fit_score_seconds': round(time.monotonic()-t0, 3),
                       'group_train_rows': forest.group_rows, 'thresholds': thr,
                       'calibration': counts(md.labels_for(severity[cal], cal_scores, thr['combined'])),
                       'selection': counts(labs), 'selection_failed': counts(labs[normals['failed'][valid]])}
            report['candidates'][name] = metrics
            fitted[name] = (forest, train_scores, thr)
            print(name, json.dumps(metrics), flush=True)
        eligible = [name for name in CANDIDATES if report['candidates'][name]['eligible']]
        if not eligible:
            report['status'] = 'no_eligible_candidate'; report_path.write_text(json.dumps(report, indent=2)+'\n')
            raise SystemExit('No eligible candidate; baseline retained')
        chosen = min(eligible, key=lambda name: selection_key(report['candidates'][name], CANDIDATES.index(name)))
        report.update(status='selection_frozen_before_retrospective_scoring', selected=chosen, selected_at=md.utc_now())
        report_path.write_text(json.dumps(report, indent=2)+'\n')
        forest, train_scores, thresholds = fitted[chosen]
        artifact = md.build_artifact(chosen, forest, md.TailModel(ft.FEATURE_KEYS).fit(X[train], flows[train]),
                                     train_scores, thresholds['combined'], normals['ids'][train].tolist(),
                                     extra={'thresholds_anomaly_only': thresholds['anomaly_only']})
        artifact['version'] = TAG
        artifact_path = md.save_artifact(artifact, artifact_dir, TAG, {'training_protocol': PROTOCOL,
                                         'candidate_script_sha256': report['script_sha256']})
        display_path = artifact_path.relative_to(md.ROOT) if artifact_path.is_relative_to(md.ROOT) else artifact_path
        report['artifact'] = {'path': str(display_path), 'sha256': md.sha256_file(artifact_path),
                              'bytes': artifact_path.stat().st_size}
        # Selection is now frozen. These are already-studied rows, never a new sealed evaluation.
        base = md.load_artifact()
        late = masks['retrospective']
        collector = np.array([not str(s).startswith('fastnear-seed') for s in normals['source'][late]])
        outputs = {'rules_only': np.where(severity[late]>=3,'high',np.where(severity[late]>=2,'medium','low'))}
        for name, art in [('baseline',base), ('candidate',artifact)]:
            outputs[name] = md.labels_for(severity[late], md.score_matrix(art,X[late],flows[late]),art['thresholds'])
        report['retrospective_normals'] = {name: {'all':counts(lab), 'collector':counts(lab[collector])}
                                           for name,lab in outputs.items()}
        labelled = cache['labelled']; campaign = np.array([campaign_key(c,r) for c,r in zip(labelled['campaign'],labelled['role'])])
        report['campaigns'] = {}; campaign_labels = {}
        for name, art in [('baseline',base), ('candidate',artifact)]:
            lab = md.labels_for(labelled['rule_sev'], md.score_matrix(art,labelled['X'],labelled['flow'].astype(str)),art['thresholds'])
            campaign_labels[name] = lab
            report['campaigns'][name] = {key:counts(lab[campaign==key]) for key in sorted(set(campaign))}
        a,b = report['retrospective_normals']['baseline']['collector'],report['retrospective_normals']['candidate']['collector']
        positive = np.isin(labelled['role'],['exploit','attempt'])
        lost = int((positive & (campaign_labels['baseline']!='low') & (campaign_labels['candidate']=='low')).sum())
        added = int((positive & (campaign_labels['baseline']=='low') & (campaign_labels['candidate']!='low')).sum())
        qualifies = b['medium_plus'] < a['medium_plus'] and b['high'] <= a['high'] and lost == 0
        report['adoption'] = {'meets_retrospective_gate':qualifies,'lost_campaign_detections':lost,
                             'added_campaign_detections':added, 'deployed':False,
                             'recommendation':'eligible for explicit root review as noise-reduction candidate only' if qualifies else 'retain baseline; candidate did not meet the prespecified gate',
                             'limits':'No untouched final test remains. Rules preserve known campaign recall by construction. Lower normal alerts does not demonstrate improved unseen-attack detection. Rules-only remains an essential comparison.'}
    if md.sha256_file(md.OUT/'intents_v1.pkl') != report['baseline_sha256']:
        raise RuntimeError('Baseline unexpectedly changed')
    report.update(status='complete', completed_at=md.utc_now(), wall_seconds=round(time.monotonic()-start,3))
    report_path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'selected':chosen,'retrospective_normals':report['retrospective_normals'],'adoption':report['adoption'],'wall_seconds':report['wall_seconds']},indent=2),flush=True)


if __name__ == '__main__':
    # Pickled model classes must retain an importable module name.
    from near.intents.train_candidate import main
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, help='Write report and candidate artifacts here; baseline remains unchanged')
    main(parser.parse_args().output_dir)
