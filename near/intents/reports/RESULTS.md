# Intents evidence

The API serves frozen `intents_v1` and rules; research candidates are rejected. Raw reports retain measurements, hashes and provenance.

| Evidence | Report |
|---|---|
| Accounting/state checks and coverage | [accounting_validation.json](accounting_validation.json) |
| Campaign mechanisms, fold metrics and linked attackers | [release_evidence_audit.json](release_evidence_audit.json) |
| Frozen model, campaigns and normal windows | [evaluation.json](evaluation.json) |
| Research transaction comparison | [transactions_v2.json](transactions_v2.json) |
| Generated recipe provenance | [synthetic_families_v2.json](synthetic_families_v2.json) |
| Earlier rejected candidates | [training_candidate.json](training_candidate.json), [head_evaluation.json](head_evaluation.json), [head_domain_check.json](head_domain_check.json) |

Accounting flags 712/712 measured sandbox credit defects and 23/23 known real exploits; it flags 0/100,098 historical normals.
Only 25,336 normals were checked; 4,984 were inconclusive and 69,778 unsupported. Of 4,014 sandbox runs, 1,189 lack direct state measurements.
Zero findings are not proof of safety. The 329 measured unbacked-burn attempts are not positive-credit defects and are not flagged high.
Real exploits repeat one technique by one actor; production accounting reconciles events, not independent balances or token authenticity.

Rules cover callback accounting, access-control abuse and resource exhaustion: 3 of 11 taxonomy categories, excluding wallet drainers.
Of 437 campaign-labelled rows, 204 show receipt-visible rule patterns, 194 signed-intent probes and 39 other calls are missed.
The 204/204 pattern match is retrospective coverage, not detection accuracy. Seven campaign rows do not reach Intents.
41/53 April detections mean only “deposit used Notify”; the April preset also has out-of-gas evidence.
The 18 May token-campaign detections are private-method probes, not token-authenticity checks; its preset is a rejected overdraw probe.

## Alerts per day

The served detector raises 0 high and 84 medium alerts on 7,400 historical normals; 80 medium alerts come from one paused-contract hour.
Per-day figures pool the 2026-10-01 paused hour. Rules plus accounting alone raise no medium/high alerts; the model adds no campaign detections.
Zero high alerts has a 95% Wilson upper bound of 0.052%, optimistic under correlated traffic; it is not a future population rate.

## Limits

1. Rules and features were developed after seeing campaigns and scouting seeds. Of 12,463 test normals, only 7,400 were independent of rule development;
   5,063 test and 2,672 calibration rows were scouting seeds. Calibration had no withdrawals and only 227 other-flow rows.
2. Research family holdouts pool four refits (204→353/430); two May families share a funder. Attacker-cluster holdout falls to 204→216/430.
   Keep each fold's alerts alongside its recall. Full-fit candidate: 14 high/7,400 normals and 26 high/40 generated benign controls; rejected.
3. Generated data are variant holdouts of four recipes. Three external exploits span two out-of-scope protocols; 500 unlabelled fresh transactions
   cover only a correlated 112-second window. Neither establishes unseen-attack accuracy. `risk` is not an attack probability.
4. Four attacker-adjacent training normals existed; research fitting excluded them, but served weights were not retrained.
   Historical rules also raised one high training and one high calibration alert that were not investigated.
5. Selection changed after calibration exposed a score ceiling; the sealed test was scored twice after a nonfunctional hash change, with identical results.
   [Initial selection](freeze_first_pass.json), [first evaluation](evaluation_sealed_run1.json), paused-traffic analysis and ablation are historical/post hoc.

Full research inputs are not bundled. Reproduce accounting with the original hashed inputs via
`uv run python -m near.intents.validate_accounting --out /tmp/accounting-validation.json`; do not overwrite shipped reports or refit served models.
