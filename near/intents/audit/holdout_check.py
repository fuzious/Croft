"""Read-only: per-fold false alarms for the rejected real_hgb candidate, family folds and attacker folds.

Uses the repo's own fit_candidate / calibrate / combined_labels on the research feature matrix. Writes nothing.
Usage: python -m near.intents.audit.holdout_check [--features near/models/transactions_v2_features.pkl]
"""
import argparse
import pickle
import time
from collections import Counter

import numpy as np
from threadpoolctl import threadpool_limits

from near.intents import train_transactions as tt


def run(features, emit=print):
    with open(features, 'rb') as f:
        d = pickle.load(f)
    X, rows = d['X'], d['records']
    source = np.array([r['source_kind'] for r in rows]); family = np.array([str(r['family']) for r in rows])
    label = np.array([r['label'] for r in rows], object)
    normal = (source == 'normal') & np.array([r['excluded'] is None for r in rows])
    masks = {k: m & normal for k, m in tt.temporal_masks([r['month'] for r in rows]).items()}
    sc = np.array([r['supported'] and r['history_complete'] for r in rows])
    for p in ('fit', 'calibration', 'selection'):
        masks[p] &= sc
    real = (source == 'real') & (label == 1) & sc
    collector = masks['retrospective'] & np.array([not str(r['source']).startswith('fastnear-seed') for r in rows])
    failed = np.array([bool(r['failed']) for r in rows])
    rule = np.array([r['rule_severity'] for r in rows])
    evid = np.maximum.reduce((rule, np.asarray(d['accounting_severity']), np.asarray(d['history_severity'])))
    zero = np.zeros(len(rows), int)
    emit(' '.join(map(str, ('fit', int(masks['fit'].sum()), 'cal', int(masks['calibration'].sum()),
                            'sel', int(masks['selection'].sum()), 'collector', int(collector.sum()),
                            'collector failed', int((collector & failed).sum()), 'real', int(real.sum()),
                            Counter(family[real].tolist())))))
    emit(f'deterministic new alerts on normals (evidence>=2 but rule<2): '
         f'{int((normal & (evid >= 2) & (rule < 2)).sum())} | on collector: '
         f'{int((collector & (evid >= 2) & (rule < 2)).sum())}')
    emit('accounting_status on collector: '
         f"{Counter(str(rows[i]['accounting_status']) for i in np.flatnonzero(collector))}")
    emit('accounting_status on all normals: '
         f"{Counter(str(rows[i]['accounting_status']) for i in np.flatnonzero(source == 'normal'))}")
    Xn = X[masks['fit']]
    empty = X[:0]
    results = {}

    def fold(name, held_mask):
        t = time.time()
        tr = real & ~held_mask
        m = tt.fit_candidate('real_hgb', Xn, X[tr], empty, np.zeros(0, int))
        thr = tt.calibrate(tt.candidate_scores(m, X[masks['calibration']]))
        s = tt.candidate_scores(m, X)
        lo = tt.combined_labels(zero, s, thr)
        both = tt.combined_labels(evid, s, thr)
        te = held_mask & real
        det = evid[te] >= 2
        r = {'training_positive_rows': int(tr.sum()), 'positive_n': int(te.sum()),
             'deterministic_medium_plus': int(det.sum()), 'combined_medium_plus': int((both[te] != 'low').sum()),
             'learned_added': int(((both[te] != 'low') & ~det).sum()),
             'collector_medium_plus': int((lo[collector] != 'low').sum()),
             'collector_high': int((lo[collector] == 'high').sum())}
        results[name] = r
        emit(f'{name:42s} train_pos={r["training_positive_rows"]:3d} thr=({thr["high"]:.4f},{thr["medium"]:.4f}) '
             f'held-out n={r["positive_n"]} rules/deterministic m+={r["deterministic_medium_plus"]} '
             f'combined m+={r["combined_medium_plus"]} learned-added={r["learned_added"]} | same model on 7,400 '
             f'normals: alerts={r["collector_medium_plus"]} (high {r["collector_high"]}), failed stratum '
             f'{int((lo[collector & failed] != "low").sum())}/{int((collector & failed).sum())} | cal alerts '
             f'{int((lo[masks["calibration"]] != "low").sum())} sel alerts '
             f'{int((lo[masks["selection"]] != "low").sum())} [{time.time()-t:.0f}s]')
        return r['combined_medium_plus']

    with threadpool_limits(4):
        tot = 0
        for held in sorted(set(family[real])):
            tot += fold(f'family held out: {held}', family == held)
        emit(f'family-held-out total {tot} / {int(real.sum())}')
        may = np.isin(family, ['token_spoofing', 'access_control'])
        a = fold('attacker held out: May fuzzer (2 families)', may)
        b = fold('attacker held out: October exploiter', family == 'callback_accounting')
        c = fold('attacker held out: April actor', family == 'resource_exhaustion')
        emit(f'attacker-held-out total {a + b + c} / {int(real.sum())}')
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--features', default=tt.CACHE, help='research feature matrix (transactions_v2_features.pkl)')
    run(parser.parse_args().features)


if __name__ == '__main__':
    main()
