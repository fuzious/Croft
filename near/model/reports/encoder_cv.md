# Code encoder: nested grouped CV on train_v1 (microsoft/unixcoder-base, 3 outer folds)

66529 rows, 8729 label-1. Pooled over 3 outer folds. Thresholds per fold from its inner validation fold (contract-code corpus negatives).

- PR-AUC 0.6361 (weighted 0.5767), ROC-AUC 0.8775
- ROC-AUC real label-1 vs contract corpus 0.7183; mutation vs contract corpus 0.8852; real label-1 vs fixed 0.5412
- Pair ranking (vulnerable > fixed): 137.5/291 = 47.3% [41.6%, 53.0%]

Protocol and limits:
- Rows: train_v1 minus the split_audit_v1_drop_ids.json ids (train sha256 checked); test_v1 never read. Every train_v1 row gets one outer-fold score (near/models/encoder_oof.jsonl).
- 3 outer folds (eval_common.group_folds, seed 20261114), not 5, for wall-clock: the encoder trains on train_v1_small rows of 2/3 of each outer-train split (~26.5k rows; the classical trainer fits ~53k), so it is at a data disadvantage. Folds differ from the classical 5-fold run.
- Epoch choice (eval_common.selection_score) and thresholds come from one inner validation fold (1/3 of the outer-train groups, all its train_v1 rows), not from inner OOF over all inner folds; the validation fold is not trained on, so the outer fold still sees nested thresholds. Selection is noisy (~100 real non-info positives per validation fold): fold 2 kept epoch 1 though epoch 2 had higher validation PR-AUC.
- Weights: eval_common.sample_weights (real total = mutation total; field `weight` on info/low rows). lr 2e-05, 2 epochs, bf16 autocast on MPS, <= 8192 padded tokens per batch, max length 512 (head+tail), comments stripped = 1.
- Header (attrs, bindgen, pub, detector hit names) is re-derived from the code text for every source, so real rows (which lack analyzer fields) and corpus rows are encoded the same way.
- Real label-1 vs its fixed version is near chance (ROC above): the encoder mostly learns mutation patterns and code style, not the audited bugs. Train real labels are noisy (split audit: ~50% agreement).

## block (target FPR 1% on contract-code corpus negatives; fold thresholds 0.8289, 0.7303, 0.7311; pooled-OOF threshold 0.7853)

| population | alarms (Wilson 95%) |
|---|---|
| recall real label-1 (all) | 19/452 = 4.2% [2.7%, 6.5%] |
| recall real, severity != info | 17/376 = 4.5% [2.8%, 7.1%] |
| recall real, severity info | 2/76 = 2.6% [0.7%, 9.1%] |
| recall mutation | 3095/8277 = 37.4% [36.4%, 38.4%] |
| FPR corpus (all) | 551/51477 = 1.1% [1.0%, 1.2%] |
| FPR corpus, contract code | 521/46714 = 1.1% [1.0%, 1.2%] |
| FPR paired fixed versions (real label-0) | 4/300 = 1.3% [0.5%, 3.4%] |
| FPR mutation originals | 76/6023 = 1.3% [1.0%, 1.6%] |
| contract files alarming (clean groups, max over public fns) | 299/6500 = 4.6% [4.1%, 5.1%] |
| files holding a real label-1 fn alarming | 32/242 = 13.2% [9.5%, 18.1%] |
| recall with pooled-OOF threshold: real 19/452 = 4.2% [2.7%, 6.5%], corpus-contract FPR 466/46714 = 1.0% [0.9%, 1.1%] | |

| vuln_class (real rows) | recall |
|---|---|
| async_reentrancy | 0/24 = 0.0% [0.0%, 13.8%] |
| ft_receiver_trust | 0/7 = 0.0% [0.0%, 35.4%] |
| gas_dos | 2/23 = 8.7% [2.4%, 26.8%] |
| logic_error | 4/162 = 2.5% [1.0%, 6.2%] |
| missing_access_control | 2/65 = 3.1% [0.8%, 10.5%] |
| missing_one_yocto | 1/21 = 4.8% [0.8%, 22.7%] |
| non_private_callback | 3/10 = 30.0% [10.8%, 60.3%] |
| oracle_price | 0/7 = 0.0% [0.0%, 35.4%] |
| precision_rounding | 3/19 = 15.8% [5.5%, 37.6%] |
| signer_auth | 2/12 = 16.7% [4.7%, 44.8%] |
| storage_staking | 1/37 = 2.7% [0.5%, 13.8%] |
| unchecked_receiver | 0/5 = 0.0% [0.0%, 43.4%] |
| unguarded_upgrade | 0/2 = 0.0% [0.0%, 65.8%] |
| unhandled_promise_result | 1/36 = 2.8% [0.5%, 14.2%] |
| unsafe_arithmetic | 0/22 = 0.0% [0.0%, 14.9%] |

## warn (target FPR 5% on contract-code corpus negatives; fold thresholds 0.2744, 0.2894, 0.3603; pooled-OOF threshold 0.3495)

| population | alarms (Wilson 95%) |
|---|---|
| recall real label-1 (all) | 96/452 = 21.2% [17.7%, 25.2%] |
| recall real, severity != info | 87/376 = 23.1% [19.2%, 27.7%] |
| recall real, severity info | 9/76 = 11.8% [6.4%, 21.0%] |
| recall mutation | 4923/8277 = 59.5% [58.4%, 60.5%] |
| FPR corpus (all) | 2748/51477 = 5.3% [5.1%, 5.5%] |
| FPR corpus, contract code | 2619/46714 = 5.6% [5.4%, 5.8%] |
| FPR paired fixed versions (real label-0) | 41/300 = 13.7% [10.2%, 18.0%] |
| FPR mutation originals | 450/6023 = 7.5% [6.8%, 8.2%] |
| contract files alarming (clean groups, max over public fns) | 1220/6500 = 18.8% [17.8%, 19.7%] |
| files holding a real label-1 fn alarming | 95/242 = 39.3% [33.3%, 45.5%] |
| recall with pooled-OOF threshold: real 83/452 = 18.4% [15.1%, 22.2%], corpus-contract FPR 2330/46714 = 5.0% [4.8%, 5.2%] | |

| vuln_class (real rows) | recall |
|---|---|
| async_reentrancy | 4/24 = 16.7% [6.7%, 35.9%] |
| ft_receiver_trust | 0/7 = 0.0% [0.0%, 35.4%] |
| gas_dos | 5/23 = 21.7% [9.7%, 41.9%] |
| logic_error | 24/162 = 14.8% [10.2%, 21.1%] |
| missing_access_control | 15/65 = 23.1% [14.5%, 34.6%] |
| missing_one_yocto | 3/21 = 14.3% [5.0%, 34.6%] |
| non_private_callback | 4/10 = 40.0% [16.8%, 68.7%] |
| oracle_price | 2/7 = 28.6% [8.2%, 64.1%] |
| precision_rounding | 13/19 = 68.4% [46.0%, 84.6%] |
| signer_auth | 7/12 = 58.3% [32.0%, 80.7%] |
| storage_staking | 8/37 = 21.6% [11.4%, 37.2%] |
| unchecked_receiver | 0/5 = 0.0% [0.0%, 43.4%] |
| unguarded_upgrade | 1/2 = 50.0% [9.5%, 90.5%] |
| unhandled_promise_result | 8/36 = 22.2% [11.7%, 38.1%] |
| unsafe_arithmetic | 2/22 = 9.1% [2.5%, 27.8%] |

## Folds

| fold | train | val | test | best epoch | seconds | val history |
|---|---|---|---|---|---|---|
| 0 | 26691 | 14784 | 22177 | 2 | 1382 | e1 sel 0.236 prauc 0.601; e2 sel 0.275 prauc 0.649 |
| 1 | 26925 | 14785 | 22176 | 2 | 1467 | e1 sel 0.313 prauc 0.572; e2 sel 0.345 prauc 0.648 |
| 2 | 26135 | 14785 | 22176 | 1 | 1791 | e1 sel 0.299 prauc 0.602; e2 sel 0.253 prauc 0.639 |

## Inner-validation experiments (outer fold 0, validation fold only; no outer-test rows used)

| run | model | strip comments | train rows | best epoch | selection | val PR-AUC |
|---|---|---|---|---|---|---|
| encoder_xp_modernbert_strip1 | modernbert | 1 | 15957 | 1 | 0.177 | 0.473 |
| encoder_xp_unixcoder_strip0 | unixcoder | 0 | 15957 | 1 | 0.158 | 0.476 |
| encoder_xp_unixcoder_strip1 | unixcoder | 1 | 15957 | 1 | 0.177 | 0.549 |

## Against the classical model on the same rows (informational: pooled-OOF thresholds, folds differ)

Classical OOF from near/model/reports/classic_cv_avg(hgb,logreg)_oof.npy (5 outer folds); mean_rank = average of the two scores' ranks.

| scores | PR-AUC | ROC real vs contract corpus | real non-info recall block | warn | mutation recall warn |
|---|---|---|---|---|---|
| encoder | 0.636 | 0.718 | 17/376 = 4.5% [2.8%, 7.1%] | 73/376 = 19.4% [15.7%, 23.7%] | 4756/8277 = 57.5% [56.4%, 58.5%] |
| classic avg(hgb,logreg) | 0.681 | 0.755 | 48/376 = 12.8% [9.8%, 16.5%] | 110/376 = 29.3% [24.9%, 34.0%] | 5141/8277 = 62.1% [61.1%, 63.2%] |
| mean_rank | 0.690 | 0.754 | 21/376 = 5.6% [3.7%, 8.4%] | 101/376 = 26.9% [22.6%, 31.6%] | 5262/8277 = 63.6% [62.5%, 64.6%] |

## Deployable checkpoint `near/models/encoder_unixcoder_final/final/checkpoint`

Trained on 47480 train_v1_small rows from 4/5 of the groups (group_folds(rows, 5, SEED + 99)[0]); epoch chosen and thresholds set on the other 1/5 (13306 train_v1 rows, never trained on): best epoch 2, block 0.8643, warn 0.3057.
Validation history: e1 sel 0.231 PR-AUC 0.648 real non-info warn 0.128; e2 sel 0.316 PR-AUC 0.694 real non-info warn 0.213

## Inference latency per function

```
{
 "n": 200,
 "prep_ms_per_fn": 0.5034804344177246,
 "mps_batch1_ms_per_fn": 9.147388935089111,
 "mps_batched_ms_per_fn": 1.7717790603637695,
 "cpu_batch1_ms_per_fn": 54.480934143066406,
 "cpu_batched_ms_per_fn": 33.062405586242676
}
```
