# Classical models: nested grouped CV on train (NEAR code risk)

Data: `near/data/train_v1.jsonl` sha256 `9359c4c1cc3fb8dc...`, 66925 rows, 396 dropped by the split audit's leak list; sealed test not read. Outer 5-fold / inner 3-fold GroupKFold over `group`, seed 20261114. Thresholds per outer fold from inner out-of-fold scores: block = 1% and warn = 5% per-function FPR on contract-code corpus negatives (not async, not test or off-chain paths). Rates pooled over outer folds, Wilson 95% CIs. Function context: {'repo': 667, 'code': 85, 'row': 65777}.

Selection objective (inner folds): Inner-fold model-selection objective: 0.75 x recall on real non-info label-1 + 0.25 x mutation recall, both at the 5% contract-code corpus FPR threshold (what the oracle's warn level would catch).

## Ranking summary

| candidate | PR-AUC | ROC-AUC | ROC-AUC real vs contract corpus | ROC-AUC real vs fixed | pair rank acc (vuln > fixed, ties half) | warn: real non-info recall | warn: FPR contract corpus |
|---|---|---|---|---|---|---|---|
| hgb | 0.680 | 0.897 | 0.743 | 0.589 | 150.0/291 = 51.5% [45.8%, 57.2%] | 113/376 = 30.1% [25.6%, 34.9%] | 2590/46714 = 5.5% [5.3%, 5.8%] |
| sgd | 0.554 | 0.837 | 0.669 | 0.573 | 167.0/291 = 57.4% [51.6%, 62.9%] | 66/376 = 17.6% [14.0%, 21.7%] | 1753/46714 = 3.8% [3.6%, 3.9%] |
| logreg | 0.616 | 0.875 | 0.739 | 0.586 | 167.0/291 = 57.4% [51.6%, 62.9%] | 105/376 = 27.9% [23.6%, 32.7%] | 2396/46714 = 5.1% [4.9%, 5.3%] |
| detectors | 0.293 | 0.652 | 0.546 | 0.513 | 152.0/291 = 52.2% [46.5%, 57.9%] | 29/376 = 7.7% [5.4%, 10.9%] | 1327/46714 = 2.8% [2.7%, 3.0%] |
| avg(hgb,logreg) | 0.681 | 0.899 | 0.755 | 0.600 | 155.0/291 = 53.3% [47.5%, 58.9%] | 116/376 = 30.9% [26.4%, 35.7%] | 2510/46714 = 5.4% [5.2%, 5.6%] |

Best by the protocol ranking (0.75 x warn real non-info recall + 0.25 x warn mutation recall): **avg(hgb,logreg)**

- block (per-function FPR 1% target): real non-info recall 48/376 = 12.8% [9.8%, 16.5%], mutation recall 3221/8277 = 38.9% [37.9%, 40.0%], contract-code corpus FPR 482/46714 = 1.0% [0.9%, 1.1%], paired fixed FPR 6/300 = 2.0% [0.9%, 4.3%]; clean files alarming 297/6500 = 4.6% [4.1%, 5.1%], files with a real vulnerability alarming 53/242 = 21.9% [17.2%, 27.5%].
- warn (per-function FPR 5% target): real non-info recall 116/376 = 30.9% [26.4%, 35.7%], mutation recall 5287/8277 = 63.9% [62.8%, 64.9%], contract-code corpus FPR 2510/46714 = 5.4% [5.2%, 5.6%], paired fixed FPR 40/300 = 13.3% [9.9%, 17.6%]; clean files alarming 1270/6500 = 19.5% [18.6%, 20.5%], files with a real vulnerability alarming 117/242 = 48.3% [42.1%, 54.6%].

## hgb

PR-AUC 0.680 (weighted 0.628), ROC-AUC 0.897, mutation vs contract corpus ROC-AUC 0.903. Params per outer fold: [{'lr': 0.1, 'leaves': 31, 'svd': 128, 'info': 0.3}, {'lr': 0.05, 'leaves': 63, 'iters': 600, 'svd': 0, 'top_tokens': 1000, 'info': 0.0}, {'lr': 0.1, 'leaves': 31, 'svd': 0, 'top_tokens': 1000, 'info': 0.3}, {'lr': 0.1, 'leaves': 31, 'svd': 128, 'info': 0.3}, {'lr': 0.05, 'leaves': 63, 'iters': 600, 'svd': 0, 'top_tokens': 1000, 'info': 0.3}].

| | block (FPR 1%) | warn (FPR 5%) |
|---|---|---|
| threshold | median 0.6525 (folds 0.5998-0.6834) | median 0.2711 (folds 0.2455-0.3136) |
| recall, real label-1 (all) | 65/452 = 14.4% [11.4%, 17.9%] | 128/452 = 28.3% [24.4%, 32.6%] |
| recall, real label-1 severity != info | 58/376 = 15.4% [12.1%, 19.4%] | 113/376 = 30.1% [25.6%, 34.9%] |
| recall, real label-1 severity = info | 7/76 = 9.2% [4.5%, 17.8%] | 15/76 = 19.7% [12.3%, 30.0%] |
| recall, mutations | 3309/8277 = 40.0% [38.9%, 41.0%] | 5266/8277 = 63.6% [62.6%, 64.7%] |
| false alarms, corpus negatives (all) | 485/51477 = 0.9% [0.9%, 1.0%] | 2694/51477 = 5.2% [5.0%, 5.4%] |
| false alarms, contract-code corpus negatives | 461/46714 = 1.0% [0.9%, 1.1%] | 2590/46714 = 5.5% [5.3%, 5.8%] |
| false alarms, paired fixed versions (real) | 8/300 = 2.7% [1.4%, 5.2%] | 35/300 = 11.7% [8.5%, 15.8%] |
| false alarms, mutation originals | 76/6023 = 1.3% [1.0%, 1.6%] | 443/6023 = 7.4% [6.7%, 8.0%] |
| contract level: clean corpus files alarming | 285/6500 = 4.4% [3.9%, 4.9%] | 1348/6500 = 20.7% [19.8%, 21.7%] |
| contract level: files holding a real vulnerability alarming | 58/242 = 24.0% [19.0%, 29.7%] | 112/242 = 46.3% [40.1%, 52.6%] |

Recall per vuln_class on real label-1 rows:

| class | block | warn |
|---|---|---|
| async_reentrancy | 2/24 = 8.3% [2.3%, 25.8%] | 3/24 = 12.5% [4.3%, 31.0%] |
| ft_receiver_trust | 0/7 = 0.0% [0.0%, 35.4%] | 0/7 = 0.0% [0.0%, 35.4%] |
| gas_dos | 6/23 = 26.1% [12.5%, 46.5%] | 10/23 = 43.5% [25.6%, 63.2%] |
| logic_error | 18/162 = 11.1% [7.1%, 16.9%] | 35/162 = 21.6% [16.0%, 28.6%] |
| missing_access_control | 10/65 = 15.4% [8.6%, 26.1%] | 23/65 = 35.4% [24.9%, 47.5%] |
| missing_one_yocto | 2/21 = 9.5% [2.7%, 28.9%] | 3/21 = 14.3% [5.0%, 34.6%] |
| non_private_callback | 7/10 = 70.0% [39.7%, 89.2%] | 7/10 = 70.0% [39.7%, 89.2%] |
| oracle_price | 1/7 = 14.3% [2.6%, 51.3%] | 5/7 = 71.4% [35.9%, 91.8%] |
| precision_rounding | 4/19 = 21.1% [8.5%, 43.3%] | 12/19 = 63.2% [41.0%, 80.9%] |
| signer_auth | 4/12 = 33.3% [13.8%, 60.9%] | 9/12 = 75.0% [46.8%, 91.1%] |
| storage_staking | 1/37 = 2.7% [0.5%, 13.8%] | 5/37 = 13.5% [5.9%, 28.0%] |
| unchecked_receiver | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] |
| unguarded_upgrade | 1/2 = 50.0% [9.5%, 90.5%] | 1/2 = 50.0% [9.5%, 90.5%] |
| unhandled_promise_result | 8/36 = 22.2% [11.7%, 38.1%] | 12/36 = 33.3% [20.2%, 49.7%] |
| unsafe_arithmetic | 1/22 = 4.5% [0.8%, 21.8%] | 3/22 = 13.6% [4.7%, 33.3%] |

## sgd

PR-AUC 0.554 (weighted 0.529), ROC-AUC 0.837, mutation vs contract corpus ROC-AUC 0.840. Params per outer fold: [{'alpha': 3e-05, 'char': 1.0, 'info': 0.3}, {'alpha': 3e-06, 'char': 1.0, 'info': 0.3}, {'alpha': 3e-05, 'char': 1.0, 'info': 0.3}, {'alpha': 3e-05, 'char': 0.0, 'info': 0.3}, {'alpha': 1e-05, 'char': 1.0, 'info': 0.3}].

| | block (FPR 1%) | warn (FPR 5%) |
|---|---|---|
| threshold | median 0.7462 (folds 0.7002-0.9984) | median 0.4421 (folds 0.2499-0.5160) |
| recall, real label-1 (all) | 19/452 = 4.2% [2.7%, 6.5%] | 73/452 = 16.2% [13.0%, 19.8%] |
| recall, real label-1 severity != info | 18/376 = 4.8% [3.0%, 7.4%] | 66/376 = 17.6% [14.0%, 21.7%] |
| recall, real label-1 severity = info | 1/76 = 1.3% [0.2%, 7.1%] | 7/76 = 9.2% [4.5%, 17.8%] |
| recall, mutations | 1618/8277 = 19.5% [18.7%, 20.4%] | 4036/8277 = 48.8% [47.7%, 49.8%] |
| false alarms, corpus negatives (all) | 305/51477 = 0.6% [0.5%, 0.7%] | 1816/51477 = 3.5% [3.4%, 3.7%] |
| false alarms, contract-code corpus negatives | 293/46714 = 0.6% [0.6%, 0.7%] | 1753/46714 = 3.8% [3.6%, 3.9%] |
| false alarms, paired fixed versions (real) | 3/300 = 1.0% [0.3%, 2.9%] | 25/300 = 8.3% [5.7%, 12.0%] |
| false alarms, mutation originals | 21/6023 = 0.3% [0.2%, 0.5%] | 212/6023 = 3.5% [3.1%, 4.0%] |
| contract level: clean corpus files alarming | 199/6500 = 3.1% [2.7%, 3.5%] | 963/6500 = 14.8% [14.0%, 15.7%] |
| contract level: files holding a real vulnerability alarming | 22/242 = 9.1% [6.1%, 13.4%] | 76/242 = 31.4% [25.9%, 37.5%] |

Recall per vuln_class on real label-1 rows:

| class | block | warn |
|---|---|---|
| async_reentrancy | 0/24 = 0.0% [0.0%, 13.8%] | 2/24 = 8.3% [2.3%, 25.8%] |
| ft_receiver_trust | 0/7 = 0.0% [0.0%, 35.4%] | 0/7 = 0.0% [0.0%, 35.4%] |
| gas_dos | 3/23 = 13.0% [4.5%, 32.1%] | 5/23 = 21.7% [9.7%, 41.9%] |
| logic_error | 1/162 = 0.6% [0.1%, 3.4%] | 15/162 = 9.3% [5.7%, 14.7%] |
| missing_access_control | 2/65 = 3.1% [0.8%, 10.5%] | 9/65 = 13.8% [7.5%, 24.3%] |
| missing_one_yocto | 1/21 = 4.8% [0.8%, 22.7%] | 3/21 = 14.3% [5.0%, 34.6%] |
| non_private_callback | 5/10 = 50.0% [23.7%, 76.3%] | 6/10 = 60.0% [31.3%, 83.2%] |
| oracle_price | 0/7 = 0.0% [0.0%, 35.4%] | 0/7 = 0.0% [0.0%, 35.4%] |
| precision_rounding | 1/19 = 5.3% [0.9%, 24.6%] | 4/19 = 21.1% [8.5%, 43.3%] |
| signer_auth | 3/12 = 25.0% [8.9%, 53.2%] | 6/12 = 50.0% [25.4%, 74.6%] |
| storage_staking | 2/37 = 5.4% [1.5%, 17.7%] | 10/37 = 27.0% [15.4%, 43.0%] |
| unchecked_receiver | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] |
| unguarded_upgrade | 0/2 = 0.0% [0.0%, 65.8%] | 1/2 = 50.0% [9.5%, 90.5%] |
| unhandled_promise_result | 1/36 = 2.8% [0.5%, 14.2%] | 11/36 = 30.6% [18.0%, 46.9%] |
| unsafe_arithmetic | 0/22 = 0.0% [0.0%, 14.9%] | 1/22 = 4.5% [0.8%, 21.8%] |

## logreg

PR-AUC 0.616 (weighted 0.590), ROC-AUC 0.875, mutation vs contract corpus ROC-AUC 0.880. Params per outer fold: [{'C': 1.0, 'char': 1.0, 'info': 0.3}, {'C': 0.3, 'char': 1.0, 'info': 0.3}, {'C': 0.3, 'char': 1.0, 'info': 0.3}, {'C': 0.3, 'char': 1.0, 'info': 0.3}, {'C': 0.3, 'char': 1.0, 'info': 0.3}].

| | block (FPR 1%) | warn (FPR 5%) |
|---|---|---|
| threshold | median 0.6434 (folds 0.6403-0.6532) | median 0.3327 (folds 0.2926-0.3429) |
| recall, real label-1 (all) | 28/452 = 6.2% [4.3%, 8.8%] | 117/452 = 25.9% [22.1%, 30.1%] |
| recall, real label-1 severity != info | 26/376 = 6.9% [4.8%, 9.9%] | 105/376 = 27.9% [23.6%, 32.7%] |
| recall, real label-1 severity = info | 2/76 = 2.6% [0.7%, 9.1%] | 12/76 = 15.8% [9.3%, 25.6%] |
| recall, mutations | 2407/8277 = 29.1% [28.1%, 30.1%] | 4755/8277 = 57.4% [56.4%, 58.5%] |
| false alarms, corpus negatives (all) | 487/51477 = 0.9% [0.9%, 1.0%] | 2495/51477 = 4.8% [4.7%, 5.0%] |
| false alarms, contract-code corpus negatives | 465/46714 = 1.0% [0.9%, 1.1%] | 2396/46714 = 5.1% [4.9%, 5.3%] |
| false alarms, paired fixed versions (real) | 5/300 = 1.7% [0.7%, 3.8%] | 41/300 = 13.7% [10.2%, 18.0%] |
| false alarms, mutation originals | 49/6023 = 0.8% [0.6%, 1.1%] | 416/6023 = 6.9% [6.3%, 7.6%] |
| contract level: clean corpus files alarming | 292/6500 = 4.5% [4.0%, 5.0%] | 1208/6500 = 18.6% [17.7%, 19.5%] |
| contract level: files holding a real vulnerability alarming | 27/242 = 11.2% [7.8%, 15.7%] | 105/242 = 43.4% [37.3%, 49.7%] |

Recall per vuln_class on real label-1 rows:

| class | block | warn |
|---|---|---|
| async_reentrancy | 0/24 = 0.0% [0.0%, 13.8%] | 4/24 = 16.7% [6.7%, 35.9%] |
| ft_receiver_trust | 0/7 = 0.0% [0.0%, 35.4%] | 0/7 = 0.0% [0.0%, 35.4%] |
| gas_dos | 3/23 = 13.0% [4.5%, 32.1%] | 9/23 = 39.1% [22.2%, 59.2%] |
| logic_error | 1/162 = 0.6% [0.1%, 3.4%] | 33/162 = 20.4% [14.9%, 27.2%] |
| missing_access_control | 1/65 = 1.5% [0.3%, 8.2%] | 16/65 = 24.6% [15.8%, 36.3%] |
| missing_one_yocto | 1/21 = 4.8% [0.8%, 22.7%] | 4/21 = 19.0% [7.7%, 40.0%] |
| non_private_callback | 5/10 = 50.0% [23.7%, 76.3%] | 6/10 = 60.0% [31.3%, 83.2%] |
| oracle_price | 0/7 = 0.0% [0.0%, 35.4%] | 4/7 = 57.1% [25.0%, 84.2%] |
| precision_rounding | 4/19 = 21.1% [8.5%, 43.3%] | 7/19 = 36.8% [19.1%, 59.0%] |
| signer_auth | 3/12 = 25.0% [8.9%, 53.2%] | 6/12 = 50.0% [25.4%, 74.6%] |
| storage_staking | 4/37 = 10.8% [4.3%, 24.7%] | 8/37 = 21.6% [11.4%, 37.2%] |
| unchecked_receiver | 0/5 = 0.0% [0.0%, 43.4%] | 1/5 = 20.0% [3.6%, 62.4%] |
| unguarded_upgrade | 0/2 = 0.0% [0.0%, 65.8%] | 1/2 = 50.0% [9.5%, 90.5%] |
| unhandled_promise_result | 6/36 = 16.7% [7.9%, 31.9%] | 16/36 = 44.4% [29.5%, 60.4%] |
| unsafe_arithmetic | 0/22 = 0.0% [0.0%, 14.9%] | 2/22 = 9.1% [2.5%, 27.8%] |

## detectors

PR-AUC 0.293 (weighted 0.311), ROC-AUC 0.652, mutation vs contract corpus ROC-AUC 0.660. Params per outer fold: [{'info': 0.3}, {'info': 0.3}, {'info': 0.3}, {'info': 0.3}, {'info': 0.3}].

| | block (FPR 1%) | warn (FPR 5%) |
|---|---|---|
| threshold | median 1.3932 (folds 1.3932-1.3932) | median 1.1055 (folds 1.1055-1.1055) |
| recall, real label-1 (all) | 7/452 = 1.5% [0.8%, 3.2%] | 29/452 = 6.4% [4.5%, 9.1%] |
| recall, real label-1 severity != info | 7/376 = 1.9% [0.9%, 3.8%] | 29/376 = 7.7% [5.4%, 10.9%] |
| recall, real label-1 severity = info | 0/76 = 0.0% [0.0%, 4.8%] | 0/76 = 0.0% [0.0%, 4.8%] |
| recall, mutations | 564/8277 = 6.8% [6.3%, 7.4%] | 2423/8277 = 29.3% [28.3%, 30.3%] |
| false alarms, corpus negatives (all) | 353/51477 = 0.7% [0.6%, 0.8%] | 1415/51477 = 2.7% [2.6%, 2.9%] |
| false alarms, contract-code corpus negatives | 310/46714 = 0.7% [0.6%, 0.7%] | 1327/46714 = 2.8% [2.7%, 3.0%] |
| false alarms, paired fixed versions (real) | 2/300 = 0.7% [0.2%, 2.4%] | 9/300 = 3.0% [1.6%, 5.6%] |
| false alarms, mutation originals | 44/6023 = 0.7% [0.5%, 1.0%] | 200/6023 = 3.3% [2.9%, 3.8%] |
| contract level: clean corpus files alarming | 189/6500 = 2.9% [2.5%, 3.3%] | 755/6500 = 11.6% [10.9%, 12.4%] |
| contract level: files holding a real vulnerability alarming | 6/242 = 2.5% [1.1%, 5.3%] | 43/242 = 17.8% [13.5%, 23.1%] |

Recall per vuln_class on real label-1 rows:

| class | block | warn |
|---|---|---|
| async_reentrancy | 0/24 = 0.0% [0.0%, 13.8%] | 0/24 = 0.0% [0.0%, 13.8%] |
| ft_receiver_trust | 0/7 = 0.0% [0.0%, 35.4%] | 0/7 = 0.0% [0.0%, 35.4%] |
| gas_dos | 0/23 = 0.0% [0.0%, 14.3%] | 6/23 = 26.1% [12.5%, 46.5%] |
| logic_error | 3/162 = 1.9% [0.6%, 5.3%] | 5/162 = 3.1% [1.3%, 7.0%] |
| missing_access_control | 1/65 = 1.5% [0.3%, 8.2%] | 2/65 = 3.1% [0.8%, 10.5%] |
| missing_one_yocto | 0/21 = 0.0% [0.0%, 15.5%] | 1/21 = 4.8% [0.8%, 22.7%] |
| non_private_callback | 0/10 = 0.0% [0.0%, 27.8%] | 2/10 = 20.0% [5.7%, 51.0%] |
| oracle_price | 0/7 = 0.0% [0.0%, 35.4%] | 3/7 = 42.9% [15.8%, 75.0%] |
| precision_rounding | 0/19 = 0.0% [0.0%, 16.8%] | 1/19 = 5.3% [0.9%, 24.6%] |
| signer_auth | 3/12 = 25.0% [8.9%, 53.2%] | 7/12 = 58.3% [32.0%, 80.7%] |
| storage_staking | 0/37 = 0.0% [0.0%, 9.4%] | 1/37 = 2.7% [0.5%, 13.8%] |
| unchecked_receiver | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] |
| unguarded_upgrade | 0/2 = 0.0% [0.0%, 65.8%] | 1/2 = 50.0% [9.5%, 90.5%] |
| unhandled_promise_result | 0/36 = 0.0% [0.0%, 9.6%] | 0/36 = 0.0% [0.0%, 9.6%] |
| unsafe_arithmetic | 0/22 = 0.0% [0.0%, 14.9%] | 0/22 = 0.0% [0.0%, 14.9%] |

## avg(hgb,logreg)

PR-AUC 0.681 (weighted 0.636), ROC-AUC 0.899, mutation vs contract corpus ROC-AUC 0.905.

| | block (FPR 1%) | warn (FPR 5%) |
|---|---|---|
| threshold | median 0.5924 (folds 0.5718-0.6083) | median 0.2830 (folds 0.2573-0.3135) |
| recall, real label-1 (all) | 51/452 = 11.3% [8.7%, 14.5%] | 133/452 = 29.4% [25.4%, 33.8%] |
| recall, real label-1 severity != info | 48/376 = 12.8% [9.8%, 16.5%] | 116/376 = 30.9% [26.4%, 35.7%] |
| recall, real label-1 severity = info | 3/76 = 3.9% [1.4%, 11.0%] | 17/76 = 22.4% [14.5%, 32.9%] |
| recall, mutations | 3221/8277 = 38.9% [37.9%, 40.0%] | 5287/8277 = 63.9% [62.8%, 64.9%] |
| false alarms, corpus negatives (all) | 502/51477 = 1.0% [0.9%, 1.1%] | 2618/51477 = 5.1% [4.9%, 5.3%] |
| false alarms, contract-code corpus negatives | 482/46714 = 1.0% [0.9%, 1.1%] | 2510/46714 = 5.4% [5.2%, 5.6%] |
| false alarms, paired fixed versions (real) | 6/300 = 2.0% [0.9%, 4.3%] | 40/300 = 13.3% [9.9%, 17.6%] |
| false alarms, mutation originals | 67/6023 = 1.1% [0.9%, 1.4%] | 434/6023 = 7.2% [6.6%, 7.9%] |
| contract level: clean corpus files alarming | 297/6500 = 4.6% [4.1%, 5.1%] | 1270/6500 = 19.5% [18.6%, 20.5%] |
| contract level: files holding a real vulnerability alarming | 53/242 = 21.9% [17.2%, 27.5%] | 117/242 = 48.3% [42.1%, 54.6%] |

Recall per vuln_class on real label-1 rows:

| class | block | warn |
|---|---|---|
| async_reentrancy | 0/24 = 0.0% [0.0%, 13.8%] | 4/24 = 16.7% [6.7%, 35.9%] |
| ft_receiver_trust | 0/7 = 0.0% [0.0%, 35.4%] | 0/7 = 0.0% [0.0%, 35.4%] |
| gas_dos | 5/23 = 21.7% [9.7%, 41.9%] | 9/23 = 39.1% [22.2%, 59.2%] |
| logic_error | 12/162 = 7.4% [4.3%, 12.5%] | 42/162 = 25.9% [19.8%, 33.2%] |
| missing_access_control | 6/65 = 9.2% [4.3%, 18.7%] | 22/65 = 33.8% [23.5%, 46.0%] |
| missing_one_yocto | 1/21 = 4.8% [0.8%, 22.7%] | 4/21 = 19.0% [7.7%, 40.0%] |
| non_private_callback | 6/10 = 60.0% [31.3%, 83.2%] | 7/10 = 70.0% [39.7%, 89.2%] |
| oracle_price | 1/7 = 14.3% [2.6%, 51.3%] | 5/7 = 71.4% [35.9%, 91.8%] |
| precision_rounding | 3/19 = 15.8% [5.5%, 37.6%] | 10/19 = 52.6% [31.7%, 72.7%] |
| signer_auth | 4/12 = 33.3% [13.8%, 60.9%] | 8/12 = 66.7% [39.1%, 86.2%] |
| storage_staking | 3/37 = 8.1% [2.8%, 21.3%] | 7/37 = 18.9% [9.5%, 34.2%] |
| unchecked_receiver | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] |
| unguarded_upgrade | 1/2 = 50.0% [9.5%, 90.5%] | 1/2 = 50.0% [9.5%, 90.5%] |
| unhandled_promise_result | 8/36 = 22.2% [11.7%, 38.1%] | 12/36 = 33.3% [20.2%, 49.7%] |
| unsafe_arithmetic | 1/22 = 4.5% [0.8%, 21.8%] | 2/22 = 9.1% [2.5%, 27.8%] |

## vuln_class head (reasons)

Multinomial logistic regression on label-1 rows of each outer-train fold (analyzer + token hashes, real rows upweighted), scored on 452 real label-1 rows of the outer-test folds.

| | macro-F1 | accuracy |
|---|---|---|
| model | 0.266 | 0.319 |
| detector_baseline | 0.181 | 0.365 |

| class | n real | F1 model | F1 detector baseline |
|---|---|---|---|
| async_reentrancy | 24 | 0.23 | 0.14 |
| ft_receiver_trust | 7 | 0.36 | 0.00 |
| gas_dos | 23 | 0.24 | 0.08 |
| logic_error | 162 | 0.35 | 0.52 |
| missing_access_control | 65 | 0.38 | 0.03 |
| missing_one_yocto | 21 | 0.14 | 0.28 |
| non_private_callback | 10 | 0.60 | 0.31 |
| oracle_price | 7 | 0.00 | 0.00 |
| precision_rounding | 19 | 0.42 | 0.48 |
| signer_auth | 12 | 0.63 | 0.48 |
| storage_staking | 37 | 0.07 | 0.04 |
| unchecked_receiver | 5 | 0.00 | 0.00 |
| unguarded_upgrade | 2 | 0.00 | 0.00 |
| unhandled_promise_result | 36 | 0.40 | 0.20 |
| unsafe_arithmetic | 22 | 0.16 | 0.16 |

## Freeze input: all-train selection for hgb

Params {'lr': 0.1, 'leaves': 31, 'svd': 0, 'top_tokens': 1000, 'info': 0.3}; thresholds from grouped OOF scores on all train: block 0.6401, warn 0.3179. Refit with `near.model.train_classic.fit_model` on all train rows (features from `load_train` + `featurize_rows`).

## Freeze input: all-train selection for logreg

Params {'C': 0.3, 'char': 1.0, 'info': 0.3}; thresholds from grouped OOF scores on all train: block 0.6487, warn 0.3368. Refit with `near.model.train_classic.fit_model` on all train rows (features from `load_train` + `featurize_rows`).

## Freeze input: all-train selection for avg(hgb,logreg)

Params {'hgb': {'lr': 0.1, 'leaves': 31, 'svd': 0, 'top_tokens': 1000, 'info': 0.3}, 'logreg': {'C': 0.3, 'char': 1.0, 'info': 0.3}}; thresholds from grouped OOF scores on all train: block 0.5905, warn 0.3124. Refit with `near.model.train_classic.fit_model` on all train rows (features from `load_train` + `featurize_rows`).

## Limits

- Labels: the split audit found real label-1 train rows only ~50% plausible on a 40-row read (Wilson 35-65%);
  severity-info findings are 17% of train positives. Real-row recall here is measured against those noisy labels.
- Corpus negatives are presumed safe, not verified; a few are vulnerable (audit read 1 clear case in 40).
- Mutation rows are synthetic; their recall says the model learns the injected patterns, not real-world bugs.
- Per-class real counts are small (oracle_price 7, unguarded_upgrade 2, unchecked_receiver 5): wide CIs.
- Features use the function text only (no file context); 85 code_from_snippet real rows derive `is_public` from
  their own `pub` keyword and have no trait information.
- Thresholds are set on inner-fold models trained on less data than the outer model, as in scripts/eval_nested.py;
  realized outer FPRs land at 1.0% / 5.1-5.5% for the learned models.
- Vulnerable vs fixed versions of the same function are ranked at about chance (pair rank ~51-57%): the models
  mostly score what kind of code a function is (state-changing DeFi logic, callbacks, auth patterns), not whether the
  specific bug is present. Real-row recall against corpus negatives partly reflects that difference in code type.
- Contract-level recall uses corpus rows of the same (group, path), which may come from a later commit than the
  vulnerable function.
