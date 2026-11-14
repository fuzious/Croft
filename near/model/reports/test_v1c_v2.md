# test_v1c: frozen_near_v2 vs frozen_near_v1 (scored once, 2026-11-14T06:57:51+00:00)

**DEVELOPMENT-INFORMED, not a sealed test.** test_v1c is test_v1 with cleaned labels. test_v1's aggregate v1 results (near/model/reports/sealed_test_v1.md) were seen before v2 was designed, and they shaped its design: the label cleaning, the context features, the ensemble. The cleaning itself was blind to model predictions. No v2 component was trained, tuned or thresholded on these rows; v2 was chosen on train_v2 nested-CV numbers by a fixed rule (`near/models/frozen_near_v2.decision.json`, written 2026-11-14T06:44:05+00:00, sha256 `1342bcfa153e7081...`, choice `ensemble_mean_rank`) before this file was scored. These numbers are optimistic relative to a fresh sealed test.

- v2 `frozen_near_v2` sha256 `8154aeb589919039...`: mean-rank ensemble of (a) classical v2: HGB (lr 0.1, 31 leaves, 300 iters, l2 1.0) on analyzer features computed with the function's file, per-detector counts, file / Cargo.toml context without the era columns and 1000 chi2-selected code tokens (train_classic_v2 ctx_fixed_noera), and (b) Qwen2.5-Coder-0.5B + LoRA r16 with a pairwise loss, merged (llm_classifier qwen05_final); risk = mean of the two models' percentiles against their held-out training scores. Thresholds block 0.9266 / warn 0.8504 (ensemble percentile scale).
- v1 `frozen_near_v1` sha256 `c76c461874c352a5...`: hist gradient boosting (lr 0.1, 31 leaves, 300 iters, l2 1.0) on signed-log analyzer features + 1000 chi2-selected binary code-token 1-3 grams. Thresholds block 0.6316 / warn 0.2908.
- Columns `v2_classical_only` / `v2_llm_only`: v2's two components alone at their own frozen thresholds (diagnostic, not deployed).

Populations (fixed before scoring): `file_available` = test rows whose source file is in the local clone at the row's commit, the rows the v2 training used (train_v2 rows without their file were excluded from v2's fit and CV because only real positives lacked it); it is the primary population, and v1 is reported on the same rows. `all_rows` = every test row; v2 then scores the rows without their file from the function alone (the service always has the file, so this is not how v2 is deployed).

## test_v1c (cleaned labels)

`near/data/test_v1c.jsonl` sha256 `fdf8dfdeb2fb8e84...`: 7473 rows, 27 groups; {'audit|0': 63, 'audit|1': 112, 'corpus|0': 4567, 'fix_commit|0': 45, 'fix_commit|1': 45, 'incident|0': 10, 'incident|1': 12, 'mutation_original|0': 1080, 'mutation|1': 1539}. Rows without their source file in the local clone: {'incident|1': 1, 'audit|1': 29, 'audit|0': 5}.

### test_v1c, population `file_available`

| | v2 | v1 | v2_classical_only | v2_llm_only |
|---|---|---|---|---|
| **block: recall, real label-1 (all)** | 6/139 = 4.3% [2.0%, 9.1%] | 6/139 = 4.3% [2.0%, 9.1%] | 4/139 = 2.9% [1.1%, 7.2%] | 4/139 = 2.9% [1.1%, 7.2%] |
| block: recall, real severity != info | 6/139 = 4.3% [2.0%, 9.1%] | 6/139 = 4.3% [2.0%, 9.1%] | 4/139 = 2.9% [1.1%, 7.2%] | 4/139 = 2.9% [1.1%, 7.2%] |
| block: recall, relabel verdict confirmed | 6/107 = 5.6% [2.6%, 11.7%] | 5/107 = 4.7% [2.0%, 10.5%] | 4/107 = 3.7% [1.5%, 9.2%] | 4/107 = 3.7% [1.5%, 9.2%] |
| block: recall, relabel verdict plausible | 0/32 = 0.0% [0.0%, 10.7%] | 1/32 = 3.1% [0.6%, 15.7%] | 0/32 = 0.0% [0.0%, 10.7%] | 0/32 = 0.0% [0.0%, 10.7%] |
| block: time split (real, dated >= 2025) | 3/65 = 4.6% [1.6%, 12.7%] | 1/65 = 1.5% [0.3%, 8.2%] | 2/65 = 3.1% [0.8%, 10.5%] | 3/65 = 4.6% [1.6%, 12.7%] |
| block: recall, mutations | 654/1539 = 42.5% [40.0%, 45.0%] | 473/1539 = 30.7% [28.5%, 33.1%] | 680/1539 = 44.2% [41.7%, 46.7%] | 398/1539 = 25.9% [23.7%, 28.1%] |
| block: false alarms, contract-code corpus | 46/3699 = 1.2% [0.9%, 1.7%] | 32/3699 = 0.9% [0.6%, 1.2%] | 39/3699 = 1.1% [0.8%, 1.4%] | 56/3699 = 1.5% [1.2%, 2.0%] |
| block: false alarms, paired fixed versions | 1/113 = 0.9% [0.2%, 4.8%] | 5/113 = 4.4% [1.9%, 9.9%] | 1/113 = 0.9% [0.2%, 4.8%] | 0/113 = 0.0% [0.0%, 3.3%] |
| block: corpus files holding no real label-1 alarming | 26/706 = 3.7% [2.5%, 5.3%] | 15/706 = 2.1% [1.3%, 3.5%] | 20/706 = 2.8% [1.8%, 4.3%] | 30/706 = 4.2% [3.0%, 6.0%] |
| block: files holding a real label-1 alarming | 12/86 = 14.0% [8.2%, 22.8%] | 9/86 = 10.5% [5.6%, 18.7%] | 8/86 = 9.3% [4.8%, 17.3%] | 10/86 = 11.6% [6.4%, 20.1%] |
| **warn: recall, real label-1 (all)** | 29/139 = 20.9% [14.9%, 28.4%] | 22/139 = 15.8% [10.7%, 22.8%] | 26/139 = 18.7% [13.1%, 26.0%] | 22/139 = 15.8% [10.7%, 22.8%] |
| warn: recall, real severity != info | 29/139 = 20.9% [14.9%, 28.4%] | 22/139 = 15.8% [10.7%, 22.8%] | 26/139 = 18.7% [13.1%, 26.0%] | 22/139 = 15.8% [10.7%, 22.8%] |
| warn: recall, relabel verdict confirmed | 24/107 = 22.4% [15.6%, 31.2%] | 18/107 = 16.8% [10.9%, 25.0%] | 22/107 = 20.6% [14.0%, 29.2%] | 16/107 = 15.0% [9.4%, 22.9%] |
| warn: recall, relabel verdict plausible | 5/32 = 15.6% [6.9%, 31.8%] | 4/32 = 12.5% [5.0%, 28.1%] | 4/32 = 12.5% [5.0%, 28.1%] | 6/32 = 18.8% [8.9%, 35.3%] |
| warn: time split (real, dated >= 2025) | 13/65 = 20.0% [12.1%, 31.3%] | 9/65 = 13.8% [7.5%, 24.3%] | 8/65 = 12.3% [6.4%, 22.5%] | 13/65 = 20.0% [12.1%, 31.3%] |
| warn: recall, mutations | 951/1539 = 61.8% [59.3%, 64.2%] | 843/1539 = 54.8% [52.3%, 57.2%] | 1011/1539 = 65.7% [63.3%, 68.0%] | 739/1539 = 48.0% [45.5%, 50.5%] |
| warn: false alarms, contract-code corpus | 218/3699 = 5.9% [5.2%, 6.7%] | 194/3699 = 5.2% [4.6%, 6.0%] | 179/3699 = 4.8% [4.2%, 5.6%] | 326/3699 = 8.8% [7.9%, 9.8%] |
| warn: false alarms, paired fixed versions | 17/113 = 15.0% [9.6%, 22.8%] | 13/113 = 11.5% [6.8%, 18.7%] | 17/113 = 15.0% [9.6%, 22.8%] | 10/113 = 8.8% [4.9%, 15.5%] |
| warn: corpus files holding no real label-1 alarming | 107/706 = 15.2% [12.7%, 18.0%] | 87/706 = 12.3% [10.1%, 15.0%] | 93/706 = 13.2% [10.9%, 15.9%] | 126/706 = 17.8% [15.2%, 20.8%] |
| warn: files holding a real label-1 alarming | 36/86 = 41.9% [32.0%, 52.4%] | 30/86 = 34.9% [25.7%, 45.4%] | 32/86 = 37.2% [27.7%, 47.8%] | 31/86 = 36.0% [26.7%, 46.6%] |
| pair rank, all real pairs | 58.0/109 = 53.2% [43.9%, 62.3%] | 52.0/109 = 47.7% [38.6%, 57.0%] | 55.5/109 = 50.9% [41.7%, 60.1%] | 62.5/109 = 57.3% [48.0%, 66.2%] |
| pair rank, vulnerable not shorter than its fix | 6.5/14 = 46.4% [24.0%, 70.4%] | 9.5/14 = 67.9% [42.0%, 86.0%] | 8.0/14 = 57.1% [32.6%, 78.6%] | 5.5/14 = 39.3% [18.8%, 64.4%] |
| pair rank, control 'shorter = riskier' | 95.5/109 = 87.6% [80.1%, 92.5%] | 95.5/109 = 87.6% [80.1%, 92.5%] | 95.5/109 = 87.6% [80.1%, 92.5%] | 95.5/109 = 87.6% [80.1%, 92.5%] |
| PR-AUC | 0.724 | 0.684 | 0.746 | 0.595 |
| ROC-AUC real vs contract corpus | 0.615 | 0.665 | 0.669 | 0.527 |
| ROC-AUC real vs paired fixed | 0.525 | 0.496 | 0.488 | 0.543 |
| held-out incidents (hacks) | 0 block / 2 warn / 9 missed of 11 | 0 block / 3 warn / 8 missed of 11 | 0 block / 1 warn / 10 missed of 11 | 0 block / 2 warn / 9 missed of 11 |

### test_v1c, population `all_rows`

| | v2 | v1 | v2_classical_only | v2_llm_only |
|---|---|---|---|---|
| **block: recall, real label-1 (all)** | 9/169 = 5.3% [2.8%, 9.8%] | 16/169 = 9.5% [5.9%, 14.8%] | 4/169 = 2.4% [0.9%, 5.9%] | 7/169 = 4.1% [2.0%, 8.3%] |
| block: recall, real severity != info | 9/169 = 5.3% [2.8%, 9.8%] | 16/169 = 9.5% [5.9%, 14.8%] | 4/169 = 2.4% [0.9%, 5.9%] | 7/169 = 4.1% [2.0%, 8.3%] |
| block: recall, relabel verdict confirmed | 8/123 = 6.5% [3.3%, 12.3%] | 9/123 = 7.3% [3.9%, 13.3%] | 4/123 = 3.3% [1.3%, 8.1%] | 6/123 = 4.9% [2.3%, 10.2%] |
| block: recall, relabel verdict plausible | 1/46 = 2.2% [0.4%, 11.3%] | 7/46 = 15.2% [7.6%, 28.2%] | 0/46 = 0.0% [0.0%, 7.7%] | 1/46 = 2.2% [0.4%, 11.3%] |
| block: time split (real, dated >= 2025) | 5/81 = 6.2% [2.7%, 13.6%] | 9/81 = 11.1% [6.0%, 19.8%] | 2/81 = 2.5% [0.7%, 8.6%] | 5/81 = 6.2% [2.7%, 13.6%] |
| block: recall, mutations | 654/1539 = 42.5% [40.0%, 45.0%] | 473/1539 = 30.7% [28.5%, 33.1%] | 680/1539 = 44.2% [41.7%, 46.7%] | 398/1539 = 25.9% [23.7%, 28.1%] |
| block: false alarms, contract-code corpus | 46/3699 = 1.2% [0.9%, 1.7%] | 32/3699 = 0.9% [0.6%, 1.2%] | 39/3699 = 1.1% [0.8%, 1.4%] | 56/3699 = 1.5% [1.2%, 2.0%] |
| block: false alarms, paired fixed versions | 1/118 = 0.8% [0.1%, 4.6%] | 5/118 = 4.2% [1.8%, 9.5%] | 1/118 = 0.8% [0.1%, 4.6%] | 0/118 = 0.0% [0.0%, 3.2%] |
| block: corpus files holding no real label-1 alarming | 26/703 = 3.7% [2.5%, 5.4%] | 15/703 = 2.1% [1.3%, 3.5%] | 20/703 = 2.8% [1.8%, 4.4%] | 29/703 = 4.1% [2.9%, 5.9%] |
| block: files holding a real label-1 alarming | 15/110 = 13.6% [8.4%, 21.3%] | 19/110 = 17.3% [11.3%, 25.4%] | 8/110 = 7.3% [3.7%, 13.7%] | 14/110 = 12.7% [7.7%, 20.2%] |
| **warn: recall, real label-1 (all)** | 36/169 = 21.3% [15.8%, 28.1%] | 36/169 = 21.3% [15.8%, 28.1%] | 31/169 = 18.3% [13.2%, 24.9%] | 28/169 = 16.6% [11.7%, 22.9%] |
| warn: recall, real severity != info | 36/169 = 21.3% [15.8%, 28.1%] | 36/169 = 21.3% [15.8%, 28.1%] | 31/169 = 18.3% [13.2%, 24.9%] | 28/169 = 16.6% [11.7%, 22.9%] |
| warn: recall, relabel verdict confirmed | 28/123 = 22.8% [16.2%, 30.9%] | 24/123 = 19.5% [13.5%, 27.4%] | 26/123 = 21.1% [14.9%, 29.2%] | 20/123 = 16.3% [10.8%, 23.8%] |
| warn: recall, relabel verdict plausible | 8/46 = 17.4% [9.1%, 30.7%] | 12/46 = 26.1% [15.6%, 40.3%] | 5/46 = 10.9% [4.7%, 23.0%] | 8/46 = 17.4% [9.1%, 30.7%] |
| warn: time split (real, dated >= 2025) | 15/81 = 18.5% [11.6%, 28.3%] | 17/81 = 21.0% [13.5%, 31.1%] | 10/81 = 12.3% [6.8%, 21.3%] | 17/81 = 21.0% [13.5%, 31.1%] |
| warn: recall, mutations | 951/1539 = 61.8% [59.3%, 64.2%] | 843/1539 = 54.8% [52.3%, 57.2%] | 1011/1539 = 65.7% [63.3%, 68.0%] | 739/1539 = 48.0% [45.5%, 50.5%] |
| warn: false alarms, contract-code corpus | 218/3699 = 5.9% [5.2%, 6.7%] | 194/3699 = 5.2% [4.6%, 6.0%] | 179/3699 = 4.8% [4.2%, 5.6%] | 326/3699 = 8.8% [7.9%, 9.8%] |
| warn: false alarms, paired fixed versions | 20/118 = 16.9% [11.2%, 24.7%] | 17/118 = 14.4% [9.2%, 21.9%] | 20/118 = 16.9% [11.2%, 24.7%] | 10/118 = 8.5% [4.7%, 14.9%] |
| warn: corpus files holding no real label-1 alarming | 106/703 = 15.1% [12.6%, 17.9%] | 87/703 = 12.4% [10.1%, 15.0%] | 93/703 = 13.2% [10.9%, 15.9%] | 124/703 = 17.6% [15.0%, 20.6%] |
| warn: files holding a real label-1 alarming | 43/110 = 39.1% [30.5%, 48.4%] | 43/110 = 39.1% [30.5%, 48.4%] | 37/110 = 33.6% [25.5%, 42.9%] | 38/110 = 34.5% [26.3%, 43.8%] |
| pair rank, all real pairs | 60.5/113 = 53.5% [44.4%, 62.5%] | 54.5/113 = 48.2% [39.2%, 57.3%] | 58.0/113 = 51.3% [42.2%, 60.3%] | 66.0/113 = 58.4% [49.2%, 67.1%] |
| pair rank, vulnerable not shorter than its fix | 6.5/14 = 46.4% [24.0%, 70.4%] | 9.5/14 = 67.9% [42.0%, 86.0%] | 8.0/14 = 57.1% [32.6%, 78.6%] | 5.5/14 = 39.3% [18.8%, 64.4%] |
| pair rank, control 'shorter = riskier' | 99.5/113 = 88.1% [80.8%, 92.8%] | 99.5/113 = 88.1% [80.8%, 92.8%] | 99.5/113 = 88.1% [80.8%, 92.8%] | 99.5/113 = 88.1% [80.8%, 92.8%] |
| PR-AUC | 0.721 | 0.685 | 0.742 | 0.595 |
| ROC-AUC real vs contract corpus | 0.609 | 0.669 | 0.652 | 0.533 |
| ROC-AUC real vs paired fixed | 0.514 | 0.504 | 0.470 | 0.542 |
| held-out incidents (hacks) | 0 block / 2 warn / 10 missed of 12 | 0 block / 3 warn / 9 missed of 12 | 0 block / 1 warn / 11 missed of 12 | 0 block / 2 warn / 10 missed of 12 |

## test_v1 (original labels, for continuity with sealed_test_v1)

`near/data/test_v1.jsonl` sha256 `8168bcf51be7537a...`: 7666 rows, 27 groups; {'audit|0': 116, 'audit|1': 236, 'corpus|0': 4567, 'fix_commit|0': 50, 'fix_commit|1': 54, 'incident|0': 11, 'incident|1': 13, 'mutation_original|0': 1080, 'mutation|1': 1539}. Rows without their source file in the local clone: {'incident|1': 1, 'audit|1': 56, 'audit|0': 11}.

### test_v1, population `file_available`

| | v2 | v1 | v2_classical_only | v2_llm_only |
|---|---|---|---|---|
| **block: recall, real label-1 (all)** | 6/246 = 2.4% [1.1%, 5.2%] | 7/246 = 2.8% [1.4%, 5.8%] | 5/246 = 2.0% [0.9%, 4.7%] | 4/246 = 1.6% [0.6%, 4.1%] |
| block: recall, real severity != info | 6/176 = 3.4% [1.6%, 7.2%] | 7/176 = 4.0% [1.9%, 8.0%] | 4/176 = 2.3% [0.9%, 5.7%] | 4/176 = 2.3% [0.9%, 5.7%] |
| block: recall, relabel verdict confirmed | n/a | n/a | n/a | n/a |
| block: recall, relabel verdict plausible | n/a | n/a | n/a | n/a |
| block: time split (real, dated >= 2025) | 3/100 = 3.0% [1.0%, 8.5%] | 1/100 = 1.0% [0.2%, 5.4%] | 3/100 = 3.0% [1.0%, 8.5%] | 3/100 = 3.0% [1.0%, 8.5%] |
| block: recall, mutations | 654/1539 = 42.5% [40.0%, 45.0%] | 473/1539 = 30.7% [28.5%, 33.1%] | 680/1539 = 44.2% [41.7%, 46.7%] | 398/1539 = 25.9% [23.7%, 28.1%] |
| block: false alarms, contract-code corpus | 46/3699 = 1.2% [0.9%, 1.7%] | 32/3699 = 0.9% [0.6%, 1.2%] | 39/3699 = 1.1% [0.8%, 1.4%] | 56/3699 = 1.5% [1.2%, 2.0%] |
| block: false alarms, paired fixed versions | 2/166 = 1.2% [0.3%, 4.3%] | 7/166 = 4.2% [2.1%, 8.4%] | 3/166 = 1.8% [0.6%, 5.2%] | 0/166 = 0.0% [0.0%, 2.3%] |
| block: corpus files holding no real label-1 alarming | 25/681 = 3.7% [2.5%, 5.4%] | 15/681 = 2.2% [1.3%, 3.6%] | 20/681 = 2.9% [1.9%, 4.5%] | 26/681 = 3.8% [2.6%, 5.5%] |
| block: files holding a real label-1 alarming | 13/126 = 10.3% [6.1%, 16.9%] | 9/126 = 7.1% [3.8%, 13.0%] | 9/126 = 7.1% [3.8%, 13.0%] | 14/126 = 11.1% [6.7%, 17.8%] |
| **warn: recall, real label-1 (all)** | 42/246 = 17.1% [12.9%, 22.3%] | 30/246 = 12.2% [8.7%, 16.9%] | 42/246 = 17.1% [12.9%, 22.3%] | 28/246 = 11.4% [8.0%, 16.0%] |
| warn: recall, real severity != info | 33/176 = 18.8% [13.7%, 25.2%] | 26/176 = 14.8% [10.3%, 20.8%] | 29/176 = 16.5% [11.7%, 22.7%] | 27/176 = 15.3% [10.8%, 21.4%] |
| warn: recall, relabel verdict confirmed | n/a | n/a | n/a | n/a |
| warn: recall, relabel verdict plausible | n/a | n/a | n/a | n/a |
| warn: time split (real, dated >= 2025) | 15/100 = 15.0% [9.3%, 23.3%] | 11/100 = 11.0% [6.3%, 18.6%] | 10/100 = 10.0% [5.5%, 17.4%] | 17/100 = 17.0% [10.9%, 25.5%] |
| warn: recall, mutations | 951/1539 = 61.8% [59.3%, 64.2%] | 843/1539 = 54.8% [52.3%, 57.2%] | 1011/1539 = 65.7% [63.3%, 68.0%] | 739/1539 = 48.0% [45.5%, 50.5%] |
| warn: false alarms, contract-code corpus | 218/3699 = 5.9% [5.2%, 6.7%] | 194/3699 = 5.2% [4.6%, 6.0%] | 179/3699 = 4.8% [4.2%, 5.6%] | 326/3699 = 8.8% [7.9%, 9.8%] |
| warn: false alarms, paired fixed versions | 25/166 = 15.1% [10.4%, 21.3%] | 18/166 = 10.8% [7.0%, 16.5%] | 31/166 = 18.7% [13.5%, 25.3%] | 16/166 = 9.6% [6.0%, 15.1%] |
| warn: corpus files holding no real label-1 alarming | 102/681 = 15.0% [12.5%, 17.9%] | 81/681 = 11.9% [9.7%, 14.5%] | 90/681 = 13.2% [10.9%, 16.0%] | 116/681 = 17.0% [14.4%, 20.0%] |
| warn: files holding a real label-1 alarming | 46/126 = 36.5% [28.6%, 45.2%] | 38/126 = 30.2% [22.8%, 38.7%] | 46/126 = 36.5% [28.6%, 45.2%] | 41/126 = 32.5% [25.0%, 41.1%] |
| pair rank, all real pairs | 85.0/162 = 52.5% [44.8%, 60.0%] | 70.0/162 = 43.2% [35.8%, 50.9%] | 77.5/162 = 47.8% [40.3%, 55.5%] | 93.0/162 = 57.4% [49.7%, 64.8%] |
| pair rank, vulnerable not shorter than its fix | 12.5/27 = 46.3% [29.2%, 64.4%] | 15.5/27 = 57.4% [39.0%, 74.0%] | 15.0/27 = 55.6% [37.3%, 72.4%] | 11.5/27 = 42.6% [26.0%, 61.0%] |
| pair rank, control 'shorter = riskier' | 136.0/162 = 84.0% [77.5%, 88.8%] | 136.0/162 = 84.0% [77.5%, 88.8%] | 136.0/162 = 84.0% [77.5%, 88.8%] | 136.0/162 = 84.0% [77.5%, 88.8%] |
| PR-AUC | 0.707 | 0.672 | 0.730 | 0.583 |
| ROC-AUC real vs contract corpus | 0.553 | 0.627 | 0.624 | 0.466 |
| ROC-AUC real vs paired fixed | 0.492 | 0.467 | 0.457 | 0.510 |
| held-out incidents (hacks) | 0 block / 2 warn / 10 missed of 12 | 0 block / 3 warn / 9 missed of 12 | 0 block / 1 warn / 11 missed of 12 | 0 block / 2 warn / 10 missed of 12 |

### test_v1, population `all_rows`

| | v2 | v1 | v2_classical_only | v2_llm_only |
|---|---|---|---|---|
| **block: recall, real label-1 (all)** | 9/303 = 3.0% [1.6%, 5.5%] | 20/303 = 6.6% [4.3%, 10.0%] | 5/303 = 1.7% [0.7%, 3.8%] | 8/303 = 2.6% [1.3%, 5.1%] |
| block: recall, real severity != info | 9/215 = 4.2% [2.2%, 7.8%] | 18/215 = 8.4% [5.4%, 12.8%] | 4/215 = 1.9% [0.7%, 4.7%] | 8/215 = 3.7% [1.9%, 7.2%] |
| block: recall, relabel verdict confirmed | n/a | n/a | n/a | n/a |
| block: recall, relabel verdict plausible | n/a | n/a | n/a | n/a |
| block: time split (real, dated >= 2025) | 5/129 = 3.9% [1.7%, 8.8%] | 10/129 = 7.8% [4.3%, 13.7%] | 3/129 = 2.3% [0.8%, 6.6%] | 5/129 = 3.9% [1.7%, 8.8%] |
| block: recall, mutations | 654/1539 = 42.5% [40.0%, 45.0%] | 473/1539 = 30.7% [28.5%, 33.1%] | 680/1539 = 44.2% [41.7%, 46.7%] | 398/1539 = 25.9% [23.7%, 28.1%] |
| block: false alarms, contract-code corpus | 46/3699 = 1.2% [0.9%, 1.7%] | 32/3699 = 0.9% [0.6%, 1.2%] | 39/3699 = 1.1% [0.8%, 1.4%] | 56/3699 = 1.5% [1.2%, 2.0%] |
| block: false alarms, paired fixed versions | 2/177 = 1.1% [0.3%, 4.0%] | 7/177 = 4.0% [1.9%, 7.9%] | 3/177 = 1.7% [0.6%, 4.9%] | 0/177 = 0.0% [0.0%, 2.1%] |
| block: corpus files holding no real label-1 alarming | 25/676 = 3.7% [2.5%, 5.4%] | 15/676 = 2.2% [1.3%, 3.6%] | 20/676 = 3.0% [1.9%, 4.5%] | 25/676 = 3.7% [2.5%, 5.4%] |
| block: files holding a real label-1 alarming | 16/161 = 9.9% [6.2%, 15.5%] | 22/161 = 13.7% [9.2%, 19.8%] | 9/161 = 5.6% [3.0%, 10.3%] | 19/161 = 11.8% [7.7%, 17.7%] |
| **warn: recall, real label-1 (all)** | 51/303 = 16.8% [13.0%, 21.5%] | 49/303 = 16.2% [12.5%, 20.7%] | 49/303 = 16.2% [12.5%, 20.7%] | 37/303 = 12.2% [9.0%, 16.4%] |
| warn: recall, real severity != info | 41/215 = 19.1% [14.4%, 24.8%] | 42/215 = 19.5% [14.8%, 25.3%] | 35/215 = 16.3% [11.9%, 21.8%] | 34/215 = 15.8% [11.5%, 21.3%] |
| warn: recall, relabel verdict confirmed | n/a | n/a | n/a | n/a |
| warn: recall, relabel verdict plausible | n/a | n/a | n/a | n/a |
| warn: time split (real, dated >= 2025) | 17/129 = 13.2% [8.4%, 20.1%] | 22/129 = 17.1% [11.5%, 24.5%] | 13/129 = 10.1% [6.0%, 16.5%] | 23/129 = 17.8% [12.2%, 25.3%] |
| warn: recall, mutations | 951/1539 = 61.8% [59.3%, 64.2%] | 843/1539 = 54.8% [52.3%, 57.2%] | 1011/1539 = 65.7% [63.3%, 68.0%] | 739/1539 = 48.0% [45.5%, 50.5%] |
| warn: false alarms, contract-code corpus | 218/3699 = 5.9% [5.2%, 6.7%] | 194/3699 = 5.2% [4.6%, 6.0%] | 179/3699 = 4.8% [4.2%, 5.6%] | 326/3699 = 8.8% [7.9%, 9.8%] |
| warn: false alarms, paired fixed versions | 28/177 = 15.8% [11.2%, 21.9%] | 22/177 = 12.4% [8.4%, 18.1%] | 34/177 = 19.2% [14.1%, 25.6%] | 16/177 = 9.0% [5.6%, 14.2%] |
| warn: corpus files holding no real label-1 alarming | 101/676 = 14.9% [12.5%, 17.8%] | 81/676 = 12.0% [9.7%, 14.6%] | 90/676 = 13.3% [11.0%, 16.1%] | 113/676 = 16.7% [14.1%, 19.7%] |
| warn: files holding a real label-1 alarming | 55/161 = 34.2% [27.3%, 41.8%] | 56/161 = 34.8% [27.9%, 42.4%] | 53/161 = 32.9% [26.1%, 40.5%] | 51/161 = 31.7% [25.0%, 39.2%] |
| pair rank, all real pairs | 89.5/172 = 52.0% [44.6%, 59.4%] | 75.5/172 = 43.9% [36.7%, 51.4%] | 82.5/172 = 48.0% [40.6%, 55.4%] | 99.5/172 = 57.8% [50.4%, 65.0%] |
| pair rank, vulnerable not shorter than its fix | 13.5/28 = 48.2% [31.1%, 65.8%] | 16.5/28 = 58.9% [40.7%, 75.0%] | 16.0/28 = 57.1% [39.1%, 73.5%] | 12.5/28 = 44.6% [28.0%, 62.6%] |
| pair rank, control 'shorter = riskier' | 145.0/172 = 84.3% [78.1%, 89.0%] | 145.0/172 = 84.3% [78.1%, 89.0%] | 145.0/172 = 84.3% [78.1%, 89.0%] | 145.0/172 = 84.3% [78.1%, 89.0%] |
| PR-AUC | 0.701 | 0.671 | 0.723 | 0.581 |
| ROC-AUC real vs contract corpus | 0.547 | 0.626 | 0.612 | 0.468 |
| ROC-AUC real vs paired fixed | 0.489 | 0.475 | 0.447 | 0.513 |
| held-out incidents (hacks) | 0 block / 2 warn / 11 missed of 13 | 0 block / 3 warn / 10 missed of 13 | 0 block / 1 warn / 12 missed of 13 | 0 block / 2 warn / 11 missed of 13 |

## Detail: v2 on test_v1c, population `file_available`

Model `frozen_near_v2` sha256 `8154aeb589919039...` (mean-rank ensemble of (a) classical v2: HGB (lr 0.1, 31 leaves, 300 iters, l2 1.0) on analyzer features computed with the function's file, per-detector counts, file / Cargo.toml context without the era columns and 1000 chi2-selected code tokens (train_classic_v2 ctx_fixed_noera), and (b) Qwen2.5-Coder-0.5B + LoRA r16 with a pairwise loss, merged (llm_classifier qwen05_final); risk = mean of the two models' percentiles against their held-out training scores), thresholds block 0.9266 / warn 0.8504 (frozen, from train OOF). Test `near/data/test_v1c.jsonl` sha256 `fdf8dfdeb2fb8e84...`: 7438 rows, 1678 label-1, 27 groups. Rows by source/label: {'audit|0': 63, 'audit|1': 112, 'corpus|0': 4567, 'fix_commit|0': 45, 'fix_commit|1': 45, 'incident|0': 10, 'incident|1': 12, 'mutation_original|0': 1080, 'mutation|1': 1539}. Checks passed before scoring: hashes, feature schema, no shared id / group / norm_hash with train.

PR-AUC 0.724 (weighted 0.641), ROC-AUC 0.811; ROC-AUC real label-1 vs contract-code corpus 0.615, mutations vs contract corpus 0.821, real vs paired fixed 0.525; pair rank (vulnerable > fixed) 58.0/109 = 53.2% [43.9%, 62.3%].

| | block | warn |
|---|---|---|
| recall, real label-1 (all) | 6/139 = 4.3% [2.0%, 9.1%] | 29/139 = 20.9% [14.9%, 28.4%] |
| recall, real label-1 severity != info | 6/139 = 4.3% [2.0%, 9.1%] | 29/139 = 20.9% [14.9%, 28.4%] |
| recall, real label-1 severity = info | n/a | n/a |
| time split (real label-1 dated >= 2025): recall | 3/65 = 4.6% [1.6%, 12.7%] | 13/65 = 20.0% [12.1%, 31.3%] |
| time split: recall, severity != info | 3/65 = 4.6% [1.6%, 12.7%] | 13/65 = 20.0% [12.1%, 31.3%] |
| recall, mutations | 654/1539 = 42.5% [40.0%, 45.0%] | 951/1539 = 61.8% [59.3%, 64.2%] |
| false alarms, corpus negatives (all) | 48/4567 = 1.1% [0.8%, 1.4%] | 236/4567 = 5.2% [4.6%, 5.8%] |
| false alarms, contract-code corpus negatives | 46/3699 = 1.2% [0.9%, 1.7%] | 218/3699 = 5.9% [5.2%, 6.7%] |
| false alarms, contract-code corpus excl. label conflicts | 46/3684 = 1.2% [0.9%, 1.7%] | 216/3684 = 5.9% [5.1%, 6.7%] |
| false alarms, paired fixed versions | 1/113 = 0.9% [0.2%, 4.8%] | 17/113 = 15.0% [9.6%, 22.8%] |
| false alarms, paired fixed excl. label conflicts | 1/109 = 0.9% [0.2%, 5.0%] | 17/109 = 15.6% [10.0%, 23.6%] |
| false alarms, mutation originals | 9/1080 = 0.8% [0.4%, 1.6%] | 99/1080 = 9.2% [7.6%, 11.0%] |
| contract level deployed rule: test corpus files holding no real label-1 alarming | 26/706 = 3.7% [2.5%, 5.3%] | 107/706 = 15.2% [12.7%, 18.0%] |
| contract level deployed rule: clean files alarming | n/a | n/a |
| contract level deployed rule: files holding a real vulnerability alarming | 12/86 = 14.0% [8.2%, 22.8%] | 36/86 = 41.9% [32.0%, 52.4%] |
| contract level protocol rule: clean files alarming | n/a | n/a |
| contract level protocol rule: files holding a real vulnerability alarming | 12/86 = 14.0% [8.2%, 22.8%] | 36/86 = 41.9% [32.0%, 52.4%] |

### Real label-1 recall by source

| | block | warn |
|---|---|---|
| audit | 5/83 = 6.0% [2.6%, 13.3%] | 22/83 = 26.5% [18.2%, 36.9%] |
| fix_commit | 1/45 = 2.2% [0.4%, 11.6%] | 5/45 = 11.1% [4.8%, 23.5%] |
| incident | 0/11 = 0.0% [0.0%, 25.9%] | 2/11 = 18.2% [5.1%, 47.7%] |

### Real label-1 (severity != info) recall by source

| | block | warn |
|---|---|---|
| audit | 5/83 = 6.0% [2.6%, 13.3%] | 22/83 = 26.5% [18.2%, 36.9%] |
| fix_commit | 1/45 = 2.2% [0.4%, 11.6%] | 5/45 = 11.1% [4.8%, 23.5%] |
| incident | 0/11 = 0.0% [0.0%, 25.9%] | 2/11 = 18.2% [5.1%, 47.7%] |

### Real label-1 recall by vuln_class

| | block | warn |
|---|---|---|
| async_reentrancy | 0/4 = 0.0% [0.0%, 49.0%] | 1/4 = 25.0% [4.6%, 69.9%] |
| ft_receiver_trust | 1/4 = 25.0% [4.6%, 69.9%] | 2/4 = 50.0% [15.0%, 85.0%] |
| gas_dos | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| logic_error | 0/50 = 0.0% [0.0%, 7.1%] | 7/50 = 14.0% [7.0%, 26.2%] |
| missing_access_control | 2/16 = 12.5% [3.5%, 36.0%] | 4/16 = 25.0% [10.2%, 49.5%] |
| missing_one_yocto | 1/8 = 12.5% [2.2%, 47.1%] | 2/8 = 25.0% [7.1%, 59.1%] |
| non_private_callback | 0/1 = 0.0% [0.0%, 79.3%] | 1/1 = 100.0% [20.7%, 100.0%] |
| oracle_price | 0/4 = 0.0% [0.0%, 49.0%] | 1/4 = 25.0% [4.6%, 69.9%] |
| precision_rounding | 1/8 = 12.5% [2.2%, 47.1%] | 2/8 = 25.0% [7.1%, 59.1%] |
| signer_auth | 1/3 = 33.3% [6.1%, 79.2%] | 2/3 = 66.7% [20.8%, 93.9%] |
| storage_staking | 0/10 = 0.0% [0.0%, 27.8%] | 2/10 = 20.0% [5.7%, 51.0%] |
| unchecked_receiver | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| unguarded_upgrade | 0/2 = 0.0% [0.0%, 65.8%] | 0/2 = 0.0% [0.0%, 65.8%] |
| unhandled_promise_result | 0/10 = 0.0% [0.0%, 27.8%] | 5/10 = 50.0% [23.7%, 76.3%] |
| unsafe_arithmetic | 0/15 = 0.0% [0.0%, 20.4%] | 0/15 = 0.0% [0.0%, 20.4%] |

### Real label-1 recall by severity

| | block | warn |
|---|---|---|
| None | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| critical | 0/7 = 0.0% [0.0%, 35.4%] | 1/7 = 14.3% [2.6%, 51.3%] |
| high | 2/43 = 4.7% [1.3%, 15.5%] | 12/43 = 27.9% [16.7%, 42.7%] |
| low | 2/39 = 5.1% [1.4%, 16.9%] | 8/39 = 20.5% [10.8%, 35.5%] |
| medium | 2/47 = 4.3% [1.2%, 14.2%] | 8/47 = 17.0% [8.9%, 30.1%] |

### Time split (>= 2025) recall by source

| | block | warn |
|---|---|---|
| audit | 2/32 = 6.2% [1.7%, 20.1%] | 7/32 = 21.9% [11.0%, 38.8%] |
| fix_commit | 1/29 = 3.4% [0.6%, 17.2%] | 4/29 = 13.8% [5.5%, 30.6%] |
| incident | 0/4 = 0.0% [0.0%, 49.0%] | 2/4 = 50.0% [15.0%, 85.0%] |

### Time split recall by vuln_class

| | block | warn |
|---|---|---|
| async_reentrancy | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| ft_receiver_trust | 0/1 = 0.0% [0.0%, 79.3%] | 1/1 = 100.0% [20.7%, 100.0%] |
| gas_dos | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| logic_error | 0/24 = 0.0% [0.0%, 13.8%] | 3/24 = 12.5% [4.3%, 31.0%] |
| missing_access_control | 2/15 = 13.3% [3.7%, 37.9%] | 3/15 = 20.0% [7.0%, 45.2%] |
| missing_one_yocto | 0/6 = 0.0% [0.0%, 39.0%] | 0/6 = 0.0% [0.0%, 39.0%] |
| non_private_callback | 0/1 = 0.0% [0.0%, 79.3%] | 1/1 = 100.0% [20.7%, 100.0%] |
| oracle_price | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| precision_rounding | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| signer_auth | 1/3 = 33.3% [6.1%, 79.2%] | 2/3 = 66.7% [20.8%, 93.9%] |
| storage_staking | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| unhandled_promise_result | 0/4 = 0.0% [0.0%, 49.0%] | 3/4 = 75.0% [30.1%, 95.4%] |
| unsafe_arithmetic | 0/4 = 0.0% [0.0%, 49.0%] | 0/4 = 0.0% [0.0%, 49.0%] |

### Time split recall by severity

| | block | warn |
|---|---|---|
| None | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| high | 2/29 = 6.9% [1.9%, 22.0%] | 8/29 = 27.6% [14.7%, 45.7%] |
| low | 0/19 = 0.0% [0.0%, 16.8%] | 2/19 = 10.5% [2.9%, 31.4%] |
| medium | 1/16 = 6.2% [1.1%, 28.3%] | 3/16 = 18.8% [6.6%, 43.0%] |

### Mutation recall by vuln_class

| | block | warn |
|---|---|---|
| async_reentrancy | 0/10 = 0.0% [0.0%, 27.8%] | 2/10 = 20.0% [5.7%, 51.0%] |
| ft_receiver_trust | 0/15 = 0.0% [0.0%, 20.4%] | 9/15 = 60.0% [35.7%, 80.2%] |
| gas_dos | 5/52 = 9.6% [4.2%, 20.6%] | 17/52 = 32.7% [21.5%, 46.2%] |
| missing_access_control | 138/347 = 39.8% [34.8%, 45.0%] | 210/347 = 60.5% [55.3%, 65.5%] |
| missing_one_yocto | 50/215 = 23.3% [18.1%, 29.3%] | 110/215 = 51.2% [44.5%, 57.8%] |
| non_private_callback | 135/166 = 81.3% [74.7%, 86.5%] | 152/166 = 91.6% [86.3%, 94.9%] |
| oracle_price | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| precision_rounding | 38/88 = 43.2% [33.3%, 53.6%] | 68/88 = 77.3% [67.5%, 84.8%] |
| signer_auth | 242/300 = 80.7% [75.8%, 84.7%] | 263/300 = 87.7% [83.5%, 90.9%] |
| storage_staking | 1/85 = 1.2% [0.2%, 6.4%] | 13/85 = 15.3% [9.2%, 24.4%] |
| unchecked_receiver | 0/14 = 0.0% [0.0%, 21.5%] | 0/14 = 0.0% [0.0%, 21.5%] |
| unguarded_upgrade | 19/47 = 40.4% [27.6%, 54.7%] | 36/47 = 76.6% [62.8%, 86.4%] |
| unhandled_promise_result | 21/86 = 24.4% [16.6%, 34.5%] | 45/86 = 52.3% [41.9%, 62.6%] |
| unsafe_arithmetic | 5/111 = 4.5% [1.9%, 10.1%] | 26/111 = 23.4% [16.5%, 32.1%] |

### Held-out incidents (hacks)

| incident | date | class | vulnerable fns | max risk | outcome | fixed version alarms at |
|---|---|---|---|---|---|---|
| Aurora Engine ETH total supply depletion via SELFDESTRUCT (GHSA-3p69-m8gg-fwmf) | 2022-06-22 | logic_error | 1 | 0.576 | **missed** | missed |
| Aurora Engine deploy_upgrade callable by anyone | 2022-01-07 | unguarded_upgrade | 1 | 0.743 | **missed** | missed |
| Aurora Engine fee stealing in NEP-141 -> ERC-20 bridging | 2022-06-10 | ft_receiver_trust | 1 | 0.661 | **missed** | missed |
| Aurora Engine infinite spend via DELEGATECALL to exit precompiles (ExitToEthereum) | 2022-04-26 | logic_error | 1 | 0.445 | **missed** | missed |
| Aurora Engine infinite spend via DELEGATECALL to exit precompiles (ExitToNear) | 2022-04-26 | logic_error | 1 | 0.432 | **missed** | missed |
| Aurora Engine relayer key manager could remove the engine's full-access key | 2024-11-11 | unhandled_promise_result | 1 | 0.304 | **missed** | missed |
| Aurora Engine silo admin methods open to anyone | 2025-08-08 | missing_access_control | 1 | 0.144 | **missed** | n/a |
| NEAR Intents deposit notification refunds not capped (ghost balances) | 2026-10-01 | logic_error | 1 | 0.803 | **missed** | missed |
| NEAR Intents second deposit-notification vulnerability (bug bounty) | 2026-10-07 | logic_error | 1 | 0.905 | **warn** | warn |
| Ref farming fake seed id in mft_on_transfer | 2021-08-09 | ft_receiver_trust | 1 | 0.637 | **missed** | missed |
| SWEAT token ft_resolve_transfer without #[private] | 2026-04-29 | non_private_callback | 1 | 0.873 | **warn** | missed |

vuln_class head on 139 real label-1 rows: accuracy 0.295, macro-F1 0.229.

Label conflicts (split audit `label_conflicts_j09.json`, test label-0 rows that are near-identical to a label-1 row): 26 rows in test.

Trivial functions (< 2 statements or body < 3 lines) are not scored by the deployed model and count as not alarming: {'incident|0': 1, 'audit|1': 5, 'fix_commit|1': 7, 'fix_commit|0': 2, 'mutation|1': 152, 'mutation_original|0': 95} test rows (source|label).

## Detail: v1 on test_v1c, population `file_available`

Model `frozen_near_v1` sha256 `c76c461874c352a5...` (hist gradient boosting (lr 0.1, 31 leaves, 300 iters, l2 1.0) on signed-log analyzer features + 1000 chi2-selected binary code-token 1-3 grams), thresholds block 0.6316 / warn 0.2908 (frozen, from train OOF). Test `near/data/test_v1c.jsonl` sha256 `fdf8dfdeb2fb8e84...`: 7438 rows, 1678 label-1, 27 groups. Rows by source/label: {'audit|0': 63, 'audit|1': 112, 'corpus|0': 4567, 'fix_commit|0': 45, 'fix_commit|1': 45, 'incident|0': 10, 'incident|1': 12, 'mutation_original|0': 1080, 'mutation|1': 1539}. Checks passed before scoring: hashes, feature schema, no shared id / group / norm_hash with train.

PR-AUC 0.684 (weighted 0.614), ROC-AUC 0.806; ROC-AUC real label-1 vs contract-code corpus 0.665, mutations vs contract corpus 0.821, real vs paired fixed 0.496; pair rank (vulnerable > fixed) 52.0/109 = 47.7% [38.6%, 57.0%].

| | block | warn |
|---|---|---|
| recall, real label-1 (all) | 6/139 = 4.3% [2.0%, 9.1%] | 22/139 = 15.8% [10.7%, 22.8%] |
| recall, real label-1 severity != info | 6/139 = 4.3% [2.0%, 9.1%] | 22/139 = 15.8% [10.7%, 22.8%] |
| recall, real label-1 severity = info | n/a | n/a |
| time split (real label-1 dated >= 2025): recall | 1/65 = 1.5% [0.3%, 8.2%] | 9/65 = 13.8% [7.5%, 24.3%] |
| time split: recall, severity != info | 1/65 = 1.5% [0.3%, 8.2%] | 9/65 = 13.8% [7.5%, 24.3%] |
| recall, mutations | 473/1539 = 30.7% [28.5%, 33.1%] | 843/1539 = 54.8% [52.3%, 57.2%] |
| false alarms, corpus negatives (all) | 33/4567 = 0.7% [0.5%, 1.0%] | 221/4567 = 4.8% [4.3%, 5.5%] |
| false alarms, contract-code corpus negatives | 32/3699 = 0.9% [0.6%, 1.2%] | 194/3699 = 5.2% [4.6%, 6.0%] |
| false alarms, contract-code corpus excl. label conflicts | 32/3684 = 0.9% [0.6%, 1.2%] | 194/3684 = 5.3% [4.6%, 6.0%] |
| false alarms, paired fixed versions | 5/113 = 4.4% [1.9%, 9.9%] | 13/113 = 11.5% [6.8%, 18.7%] |
| false alarms, paired fixed excl. label conflicts | 5/109 = 4.6% [2.0%, 10.3%] | 13/109 = 11.9% [7.1%, 19.3%] |
| false alarms, mutation originals | 16/1080 = 1.5% [0.9%, 2.4%] | 106/1080 = 9.8% [8.2%, 11.7%] |
| contract level deployed rule: test corpus files holding no real label-1 alarming | 15/706 = 2.1% [1.3%, 3.5%] | 87/706 = 12.3% [10.1%, 15.0%] |
| contract level deployed rule: clean files alarming | n/a | n/a |
| contract level deployed rule: files holding a real vulnerability alarming | 9/86 = 10.5% [5.6%, 18.7%] | 30/86 = 34.9% [25.7%, 45.4%] |
| contract level protocol rule: clean files alarming | n/a | n/a |
| contract level protocol rule: files holding a real vulnerability alarming | 9/86 = 10.5% [5.6%, 18.7%] | 30/86 = 34.9% [25.7%, 45.4%] |

### Real label-1 recall by source

| | block | warn |
|---|---|---|
| audit | 5/83 = 6.0% [2.6%, 13.3%] | 16/83 = 19.3% [12.2%, 29.0%] |
| fix_commit | 1/45 = 2.2% [0.4%, 11.6%] | 3/45 = 6.7% [2.3%, 17.9%] |
| incident | 0/11 = 0.0% [0.0%, 25.9%] | 3/11 = 27.3% [9.7%, 56.6%] |

### Real label-1 (severity != info) recall by source

| | block | warn |
|---|---|---|
| audit | 5/83 = 6.0% [2.6%, 13.3%] | 16/83 = 19.3% [12.2%, 29.0%] |
| fix_commit | 1/45 = 2.2% [0.4%, 11.6%] | 3/45 = 6.7% [2.3%, 17.9%] |
| incident | 0/11 = 0.0% [0.0%, 25.9%] | 3/11 = 27.3% [9.7%, 56.6%] |

### Real label-1 recall by vuln_class

| | block | warn |
|---|---|---|
| async_reentrancy | 0/4 = 0.0% [0.0%, 49.0%] | 1/4 = 25.0% [4.6%, 69.9%] |
| ft_receiver_trust | 1/4 = 25.0% [4.6%, 69.9%] | 1/4 = 25.0% [4.6%, 69.9%] |
| gas_dos | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| logic_error | 1/50 = 2.0% [0.4%, 10.5%] | 8/50 = 16.0% [8.3%, 28.5%] |
| missing_access_control | 0/16 = 0.0% [0.0%, 19.4%] | 1/16 = 6.2% [1.1%, 28.3%] |
| missing_one_yocto | 1/8 = 12.5% [2.2%, 47.1%] | 1/8 = 12.5% [2.2%, 47.1%] |
| non_private_callback | 0/1 = 0.0% [0.0%, 79.3%] | 1/1 = 100.0% [20.7%, 100.0%] |
| oracle_price | 0/4 = 0.0% [0.0%, 49.0%] | 0/4 = 0.0% [0.0%, 49.0%] |
| precision_rounding | 0/8 = 0.0% [0.0%, 32.4%] | 1/8 = 12.5% [2.2%, 47.1%] |
| signer_auth | 1/3 = 33.3% [6.1%, 79.2%] | 2/3 = 66.7% [20.8%, 93.9%] |
| storage_staking | 2/10 = 20.0% [5.7%, 51.0%] | 3/10 = 30.0% [10.8%, 60.3%] |
| unchecked_receiver | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| unguarded_upgrade | 0/2 = 0.0% [0.0%, 65.8%] | 0/2 = 0.0% [0.0%, 65.8%] |
| unhandled_promise_result | 0/10 = 0.0% [0.0%, 27.8%] | 3/10 = 30.0% [10.8%, 60.3%] |
| unsafe_arithmetic | 0/15 = 0.0% [0.0%, 20.4%] | 0/15 = 0.0% [0.0%, 20.4%] |

### Real label-1 recall by severity

| | block | warn |
|---|---|---|
| None | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| critical | 0/7 = 0.0% [0.0%, 35.4%] | 0/7 = 0.0% [0.0%, 35.4%] |
| high | 1/43 = 2.3% [0.4%, 12.1%] | 7/43 = 16.3% [8.1%, 30.0%] |
| low | 2/39 = 5.1% [1.4%, 16.9%] | 5/39 = 12.8% [5.6%, 26.7%] |
| medium | 3/47 = 6.4% [2.2%, 17.2%] | 10/47 = 21.3% [12.0%, 34.9%] |

### Time split (>= 2025) recall by source

| | block | warn |
|---|---|---|
| audit | 1/32 = 3.1% [0.6%, 15.7%] | 4/32 = 12.5% [5.0%, 28.1%] |
| fix_commit | 0/29 = 0.0% [0.0%, 11.7%] | 2/29 = 6.9% [1.9%, 22.0%] |
| incident | 0/4 = 0.0% [0.0%, 49.0%] | 3/4 = 75.0% [30.1%, 95.4%] |

### Time split recall by vuln_class

| | block | warn |
|---|---|---|
| async_reentrancy | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| ft_receiver_trust | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| gas_dos | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| logic_error | 0/24 = 0.0% [0.0%, 13.8%] | 3/24 = 12.5% [4.3%, 31.0%] |
| missing_access_control | 0/15 = 0.0% [0.0%, 20.4%] | 1/15 = 6.7% [1.2%, 29.8%] |
| missing_one_yocto | 0/6 = 0.0% [0.0%, 39.0%] | 0/6 = 0.0% [0.0%, 39.0%] |
| non_private_callback | 0/1 = 0.0% [0.0%, 79.3%] | 1/1 = 100.0% [20.7%, 100.0%] |
| oracle_price | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| precision_rounding | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| signer_auth | 1/3 = 33.3% [6.1%, 79.2%] | 2/3 = 66.7% [20.8%, 93.9%] |
| storage_staking | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| unhandled_promise_result | 0/4 = 0.0% [0.0%, 49.0%] | 2/4 = 50.0% [15.0%, 85.0%] |
| unsafe_arithmetic | 0/4 = 0.0% [0.0%, 49.0%] | 0/4 = 0.0% [0.0%, 49.0%] |

### Time split recall by severity

| | block | warn |
|---|---|---|
| None | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| high | 1/29 = 3.4% [0.6%, 17.2%] | 5/29 = 17.2% [7.6%, 34.5%] |
| low | 0/19 = 0.0% [0.0%, 16.8%] | 1/19 = 5.3% [0.9%, 24.6%] |
| medium | 0/16 = 0.0% [0.0%, 19.4%] | 3/16 = 18.8% [6.6%, 43.0%] |

### Mutation recall by vuln_class

| | block | warn |
|---|---|---|
| async_reentrancy | 0/10 = 0.0% [0.0%, 27.8%] | 2/10 = 20.0% [5.7%, 51.0%] |
| ft_receiver_trust | 0/15 = 0.0% [0.0%, 20.4%] | 8/15 = 53.3% [30.1%, 75.2%] |
| gas_dos | 4/52 = 7.7% [3.0%, 18.2%] | 16/52 = 30.8% [19.9%, 44.3%] |
| missing_access_control | 44/347 = 12.7% [9.6%, 16.6%] | 180/347 = 51.9% [46.6%, 57.1%] |
| missing_one_yocto | 9/215 = 4.2% [2.2%, 7.8%] | 61/215 = 28.4% [22.8%, 34.7%] |
| non_private_callback | 132/166 = 79.5% [72.7%, 85.0%] | 148/166 = 89.2% [83.5%, 93.0%] |
| oracle_price | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| precision_rounding | 46/88 = 52.3% [42.0%, 62.4%] | 67/88 = 76.1% [66.3%, 83.8%] |
| signer_auth | 210/300 = 70.0% [64.6%, 74.9%] | 262/300 = 87.3% [83.1%, 90.6%] |
| storage_staking | 0/85 = 0.0% [0.0%, 4.3%] | 9/85 = 10.6% [5.7%, 18.9%] |
| unchecked_receiver | 0/14 = 0.0% [0.0%, 21.5%] | 1/14 = 7.1% [1.3%, 31.5%] |
| unguarded_upgrade | 18/47 = 38.3% [25.8%, 52.6%] | 38/47 = 80.9% [67.5%, 89.6%] |
| unhandled_promise_result | 7/86 = 8.1% [4.0%, 15.9%] | 36/86 = 41.9% [32.0%, 52.4%] |
| unsafe_arithmetic | 3/111 = 2.7% [0.9%, 7.6%] | 15/111 = 13.5% [8.4%, 21.1%] |

### Held-out incidents (hacks)

| incident | date | class | vulnerable fns | max risk | outcome | fixed version alarms at |
|---|---|---|---|---|---|---|
| Aurora Engine ETH total supply depletion via SELFDESTRUCT (GHSA-3p69-m8gg-fwmf) | 2022-06-22 | logic_error | 1 | 0.031 | **missed** | missed |
| Aurora Engine deploy_upgrade callable by anyone | 2022-01-07 | unguarded_upgrade | 1 | 0.146 | **missed** | missed |
| Aurora Engine fee stealing in NEP-141 -> ERC-20 bridging | 2022-06-10 | ft_receiver_trust | 1 | 0.158 | **missed** | missed |
| Aurora Engine infinite spend via DELEGATECALL to exit precompiles (ExitToEthereum) | 2022-04-26 | logic_error | 1 | 0.040 | **missed** | missed |
| Aurora Engine infinite spend via DELEGATECALL to exit precompiles (ExitToNear) | 2022-04-26 | logic_error | 1 | 0.046 | **missed** | missed |
| Aurora Engine relayer key manager could remove the engine's full-access key | 2024-11-11 | unhandled_promise_result | 1 | 0.017 | **missed** | missed |
| Aurora Engine silo admin methods open to anyone | 2025-08-08 | missing_access_control | 1 | 0.009 | **missed** | n/a |
| NEAR Intents deposit notification refunds not capped (ghost balances) | 2026-10-01 | logic_error | 1 | 0.384 | **warn** | missed |
| NEAR Intents second deposit-notification vulnerability (bug bounty) | 2026-10-07 | logic_error | 1 | 0.418 | **warn** | warn |
| Ref farming fake seed id in mft_on_transfer | 2021-08-09 | ft_receiver_trust | 1 | 0.221 | **missed** | missed |
| SWEAT token ft_resolve_transfer without #[private] | 2026-04-29 | non_private_callback | 1 | 0.404 | **warn** | missed |

vuln_class head on 139 real label-1 rows: accuracy 0.309, macro-F1 0.233.

Label conflicts (split audit `label_conflicts_j09.json`, test label-0 rows that are near-identical to a label-1 row): 26 rows in test.

Trivial functions (< 2 statements or body < 3 lines) are not scored by the deployed model and count as not alarming: {'incident|0': 1, 'audit|1': 5, 'fix_commit|1': 7, 'fix_commit|0': 2, 'mutation|1': 152, 'mutation_original|0': 95} test rows (source|label).

## Detail: v1 on test_v1, population `all_rows`

Model `frozen_near_v1` sha256 `c76c461874c352a5...` (hist gradient boosting (lr 0.1, 31 leaves, 300 iters, l2 1.0) on signed-log analyzer features + 1000 chi2-selected binary code-token 1-3 grams), thresholds block 0.6316 / warn 0.2908 (frozen, from train OOF). Test `near/data/test_v1.jsonl` sha256 `8168bcf51be7537a...`: 7666 rows, 1842 label-1, 27 groups. Rows by source/label: {'audit|0': 116, 'audit|1': 236, 'corpus|0': 4567, 'fix_commit|0': 50, 'fix_commit|1': 54, 'incident|0': 11, 'incident|1': 13, 'mutation_original|0': 1080, 'mutation|1': 1539}. Checks passed before scoring: hashes, feature schema, no shared id / group / norm_hash with train.

PR-AUC 0.671 (weighted 0.628), ROC-AUC 0.786; ROC-AUC real label-1 vs contract-code corpus 0.626, mutations vs contract corpus 0.821, real vs paired fixed 0.475; pair rank (vulnerable > fixed) 75.5/172 = 43.9% [36.7%, 51.4%].

| | block | warn |
|---|---|---|
| recall, real label-1 (all) | 20/303 = 6.6% [4.3%, 10.0%] | 49/303 = 16.2% [12.5%, 20.7%] |
| recall, real label-1 severity != info | 18/215 = 8.4% [5.4%, 12.8%] | 42/215 = 19.5% [14.8%, 25.3%] |
| recall, real label-1 severity = info | 2/88 = 2.3% [0.6%, 7.9%] | 7/88 = 8.0% [3.9%, 15.5%] |
| time split (real label-1 dated >= 2025): recall | 10/129 = 7.8% [4.3%, 13.7%] | 22/129 = 17.1% [11.5%, 24.5%] |
| time split: recall, severity != info | 10/103 = 9.7% [5.4%, 17.0%] | 21/103 = 20.4% [13.7%, 29.2%] |
| recall, mutations | 473/1539 = 30.7% [28.5%, 33.1%] | 843/1539 = 54.8% [52.3%, 57.2%] |
| false alarms, corpus negatives (all) | 33/4567 = 0.7% [0.5%, 1.0%] | 221/4567 = 4.8% [4.3%, 5.5%] |
| false alarms, contract-code corpus negatives | 32/3699 = 0.9% [0.6%, 1.2%] | 194/3699 = 5.2% [4.6%, 6.0%] |
| false alarms, contract-code corpus excl. label conflicts | 32/3684 = 0.9% [0.6%, 1.2%] | 194/3684 = 5.3% [4.6%, 6.0%] |
| false alarms, paired fixed versions | 7/177 = 4.0% [1.9%, 7.9%] | 22/177 = 12.4% [8.4%, 18.1%] |
| false alarms, paired fixed excl. label conflicts | 7/170 = 4.1% [2.0%, 8.3%] | 22/170 = 12.9% [8.7%, 18.8%] |
| false alarms, mutation originals | 16/1080 = 1.5% [0.9%, 2.4%] | 106/1080 = 9.8% [8.2%, 11.7%] |
| contract level deployed rule: test corpus files holding no real label-1 alarming | 15/676 = 2.2% [1.3%, 3.6%] | 81/676 = 12.0% [9.7%, 14.6%] |
| contract level deployed rule: clean files alarming | n/a | n/a |
| contract level deployed rule: files holding a real vulnerability alarming | 22/161 = 13.7% [9.2%, 19.8%] | 56/161 = 34.8% [27.9%, 42.4%] |
| contract level protocol rule: clean files alarming | n/a | n/a |
| contract level protocol rule: files holding a real vulnerability alarming | 22/161 = 13.7% [9.2%, 19.8%] | 56/161 = 34.8% [27.9%, 42.4%] |

### Real label-1 recall by source

| | block | warn |
|---|---|---|
| audit | 19/236 = 8.1% [5.2%, 12.2%] | 42/236 = 17.8% [13.4%, 23.2%] |
| fix_commit | 1/54 = 1.9% [0.3%, 9.8%] | 4/54 = 7.4% [2.9%, 17.6%] |
| incident | 0/13 = 0.0% [0.0%, 22.8%] | 3/13 = 23.1% [8.2%, 50.3%] |

### Real label-1 (severity != info) recall by source

| | block | warn |
|---|---|---|
| audit | 17/148 = 11.5% [7.3%, 17.6%] | 35/148 = 23.6% [17.5%, 31.1%] |
| fix_commit | 1/54 = 1.9% [0.3%, 9.8%] | 4/54 = 7.4% [2.9%, 17.6%] |
| incident | 0/13 = 0.0% [0.0%, 22.8%] | 3/13 = 23.1% [8.2%, 50.3%] |

### Real label-1 recall by vuln_class

| | block | warn |
|---|---|---|
| None | 0/1 = 0.0% [0.0%, 79.3%] | 1/1 = 100.0% [20.7%, 100.0%] |
| async_reentrancy | 0/4 = 0.0% [0.0%, 49.0%] | 1/4 = 25.0% [4.6%, 69.9%] |
| ft_receiver_trust | 2/6 = 33.3% [9.7%, 70.0%] | 2/6 = 33.3% [9.7%, 70.0%] |
| gas_dos | 1/16 = 6.2% [1.1%, 28.3%] | 3/16 = 18.8% [6.6%, 43.0%] |
| logic_error | 4/120 = 3.3% [1.3%, 8.3%] | 11/120 = 9.2% [5.2%, 15.7%] |
| missing_access_control | 3/46 = 6.5% [2.2%, 17.5%] | 6/46 = 13.0% [6.1%, 25.7%] |
| missing_one_yocto | 0/10 = 0.0% [0.0%, 27.8%] | 1/10 = 10.0% [1.8%, 40.4%] |
| non_private_callback | 0/3 = 0.0% [0.0%, 56.2%] | 1/3 = 33.3% [6.1%, 79.2%] |
| oracle_price | 1/16 = 6.2% [1.1%, 28.3%] | 3/16 = 18.8% [6.6%, 43.0%] |
| precision_rounding | 0/13 = 0.0% [0.0%, 22.8%] | 1/13 = 7.7% [1.4%, 33.3%] |
| signer_auth | 1/3 = 33.3% [6.1%, 79.2%] | 1/3 = 33.3% [6.1%, 79.2%] |
| storage_staking | 4/21 = 19.0% [7.7%, 40.0%] | 6/21 = 28.6% [13.8%, 50.0%] |
| unchecked_receiver | 0/2 = 0.0% [0.0%, 65.8%] | 0/2 = 0.0% [0.0%, 65.8%] |
| unguarded_upgrade | 0/4 = 0.0% [0.0%, 49.0%] | 0/4 = 0.0% [0.0%, 49.0%] |
| unhandled_promise_result | 4/20 = 20.0% [8.1%, 41.6%] | 12/20 = 60.0% [38.7%, 78.1%] |
| unsafe_arithmetic | 0/18 = 0.0% [0.0%, 17.6%] | 0/18 = 0.0% [0.0%, 17.6%] |

### Real label-1 recall by severity

| | block | warn |
|---|---|---|
| None | 0/14 = 0.0% [0.0%, 21.5%] | 3/14 = 21.4% [7.6%, 47.6%] |
| critical | 1/8 = 12.5% [2.2%, 47.1%] | 1/8 = 12.5% [2.2%, 47.1%] |
| high | 3/54 = 5.6% [1.9%, 15.1%] | 9/54 = 16.7% [9.0%, 28.7%] |
| info | 2/88 = 2.3% [0.6%, 7.9%] | 7/88 = 8.0% [3.9%, 15.5%] |
| low | 2/60 = 3.3% [0.9%, 11.4%] | 8/60 = 13.3% [6.9%, 24.2%] |
| medium | 12/79 = 15.2% [8.9%, 24.7%] | 21/79 = 26.6% [18.1%, 37.2%] |

### Time split (>= 2025) recall by source

| | block | warn |
|---|---|---|
| audit | 10/87 = 11.5% [6.4%, 19.9%] | 16/87 = 18.4% [11.6%, 27.8%] |
| fix_commit | 0/37 = 0.0% [0.0%, 9.4%] | 3/37 = 8.1% [2.8%, 21.3%] |
| incident | 0/5 = 0.0% [0.0%, 43.4%] | 3/5 = 60.0% [23.1%, 88.2%] |

### Time split recall by vuln_class

| | block | warn |
|---|---|---|
| None | 0/1 = 0.0% [0.0%, 79.3%] | 1/1 = 100.0% [20.7%, 100.0%] |
| async_reentrancy | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| ft_receiver_trust | 1/2 = 50.0% [9.5%, 90.5%] | 1/2 = 50.0% [9.5%, 90.5%] |
| gas_dos | 0/5 = 0.0% [0.0%, 43.4%] | 1/5 = 20.0% [3.6%, 62.4%] |
| logic_error | 1/38 = 2.6% [0.5%, 13.5%] | 3/38 = 7.9% [2.7%, 20.8%] |
| missing_access_control | 2/38 = 5.3% [1.5%, 17.3%] | 5/38 = 13.2% [5.8%, 27.3%] |
| missing_one_yocto | 0/6 = 0.0% [0.0%, 39.0%] | 0/6 = 0.0% [0.0%, 39.0%] |
| non_private_callback | 0/2 = 0.0% [0.0%, 65.8%] | 1/2 = 50.0% [9.5%, 90.5%] |
| oracle_price | 1/5 = 20.0% [3.6%, 62.4%] | 2/5 = 40.0% [11.8%, 76.9%] |
| precision_rounding | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| signer_auth | 1/3 = 33.3% [6.1%, 79.2%] | 1/3 = 33.3% [6.1%, 79.2%] |
| storage_staking | 1/8 = 12.5% [2.2%, 47.1%] | 1/8 = 12.5% [2.2%, 47.1%] |
| unguarded_upgrade | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| unhandled_promise_result | 3/8 = 37.5% [13.7%, 69.4%] | 6/8 = 75.0% [40.9%, 92.9%] |
| unsafe_arithmetic | 0/6 = 0.0% [0.0%, 39.0%] | 0/6 = 0.0% [0.0%, 39.0%] |

### Time split recall by severity

| | block | warn |
|---|---|---|
| None | 0/6 = 0.0% [0.0%, 39.0%] | 3/6 = 50.0% [18.8%, 81.2%] |
| critical | 1/4 = 25.0% [4.6%, 69.9%] | 1/4 = 25.0% [4.6%, 69.9%] |
| high | 3/38 = 7.9% [2.7%, 20.8%] | 6/38 = 15.8% [7.4%, 30.4%] |
| info | 0/26 = 0.0% [0.0%, 12.9%] | 1/26 = 3.8% [0.7%, 18.9%] |
| low | 1/27 = 3.7% [0.7%, 18.3%] | 2/27 = 7.4% [2.1%, 23.4%] |
| medium | 5/28 = 17.9% [7.9%, 35.6%] | 9/28 = 32.1% [17.9%, 50.7%] |

### Mutation recall by vuln_class

| | block | warn |
|---|---|---|
| async_reentrancy | 0/10 = 0.0% [0.0%, 27.8%] | 2/10 = 20.0% [5.7%, 51.0%] |
| ft_receiver_trust | 0/15 = 0.0% [0.0%, 20.4%] | 8/15 = 53.3% [30.1%, 75.2%] |
| gas_dos | 4/52 = 7.7% [3.0%, 18.2%] | 16/52 = 30.8% [19.9%, 44.3%] |
| missing_access_control | 44/347 = 12.7% [9.6%, 16.6%] | 180/347 = 51.9% [46.6%, 57.1%] |
| missing_one_yocto | 9/215 = 4.2% [2.2%, 7.8%] | 61/215 = 28.4% [22.8%, 34.7%] |
| non_private_callback | 132/166 = 79.5% [72.7%, 85.0%] | 148/166 = 89.2% [83.5%, 93.0%] |
| oracle_price | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| precision_rounding | 46/88 = 52.3% [42.0%, 62.4%] | 67/88 = 76.1% [66.3%, 83.8%] |
| signer_auth | 210/300 = 70.0% [64.6%, 74.9%] | 262/300 = 87.3% [83.1%, 90.6%] |
| storage_staking | 0/85 = 0.0% [0.0%, 4.3%] | 9/85 = 10.6% [5.7%, 18.9%] |
| unchecked_receiver | 0/14 = 0.0% [0.0%, 21.5%] | 1/14 = 7.1% [1.3%, 31.5%] |
| unguarded_upgrade | 18/47 = 38.3% [25.8%, 52.6%] | 38/47 = 80.9% [67.5%, 89.6%] |
| unhandled_promise_result | 7/86 = 8.1% [4.0%, 15.9%] | 36/86 = 41.9% [32.0%, 52.4%] |
| unsafe_arithmetic | 3/111 = 2.7% [0.9%, 7.6%] | 15/111 = 13.5% [8.4%, 21.1%] |

### Held-out incidents (hacks)

| incident | date | class | vulnerable fns | max risk | outcome | fixed version alarms at |
|---|---|---|---|---|---|---|
| Aurora Engine ETH total supply depletion via SELFDESTRUCT (GHSA-3p69-m8gg-fwmf) | 2022-06-22 | logic_error | 1 | 0.031 | **missed** | missed |
| Aurora Engine deploy_upgrade callable by anyone | 2022-01-07 | unguarded_upgrade | 1 | 0.146 | **missed** | missed |
| Aurora Engine fee stealing in NEP-141 -> ERC-20 bridging | 2022-06-10 | ft_receiver_trust | 1 | 0.158 | **missed** | missed |
| Aurora Engine forged withdrawal receipts (Rainbow Bridge withdrawal logic error) | 2022-06-16 | logic_error | 1 | 0.008 | **missed** | missed |
| Aurora Engine infinite spend via DELEGATECALL to exit precompiles (ExitToEthereum) | 2022-04-26 | logic_error | 1 | 0.040 | **missed** | missed |
| Aurora Engine infinite spend via DELEGATECALL to exit precompiles (ExitToNear) | 2022-04-26 | logic_error | 1 | 0.046 | **missed** | missed |
| Aurora Engine relayer key manager could remove the engine's full-access key | 2024-11-11 | unhandled_promise_result | 1 | 0.017 | **missed** | missed |
| Aurora Engine silo admin methods open to anyone | 2025-08-08 | missing_access_control | 1 | 0.009 | **missed** | n/a |
| NEAR Intents deposit notification refunds not capped (ghost balances) | 2026-10-01 | unhandled_promise_result | 1 | 0.384 | **warn** | missed |
| NEAR Intents second deposit-notification vulnerability (bug bounty) | 2026-10-07 | None | 1 | 0.418 | **warn** | warn |
| Ref farming fake seed id in mft_on_transfer | 2021-08-09 | ft_receiver_trust | 1 | 0.221 | **missed** | missed |
| Rhea Finance margin trading slippage check double-counts reused swap outputs | 2026-04-16 | logic_error | 1 | 0.029 | **missed** | n/a |
| SWEAT token ft_resolve_transfer without #[private] | 2026-04-29 | non_private_callback | 1 | 0.404 | **warn** | missed |

vuln_class head on 302 real label-1 rows: accuracy 0.291, macro-F1 0.239.

Label conflicts (split audit `label_conflicts_j09.json`, test label-0 rows that are near-identical to a label-1 row): 29 rows in test.

Trivial functions (< 2 statements or body < 3 lines) are not scored by the deployed model and count as not alarming: {'incident|0': 1, 'audit|1': 29, 'audit|0': 3, 'fix_commit|1': 8, 'fix_commit|0': 2, 'mutation|1': 152, 'mutation_original|0': 95} test rows (source|label).

## Detail: v2 on test_v1, population `all_rows`

Model `frozen_near_v2` sha256 `8154aeb589919039...` (mean-rank ensemble of (a) classical v2: HGB (lr 0.1, 31 leaves, 300 iters, l2 1.0) on analyzer features computed with the function's file, per-detector counts, file / Cargo.toml context without the era columns and 1000 chi2-selected code tokens (train_classic_v2 ctx_fixed_noera), and (b) Qwen2.5-Coder-0.5B + LoRA r16 with a pairwise loss, merged (llm_classifier qwen05_final); risk = mean of the two models' percentiles against their held-out training scores), thresholds block 0.9266 / warn 0.8504 (frozen, from train OOF). Test `near/data/test_v1.jsonl` sha256 `8168bcf51be7537a...`: 7666 rows, 1842 label-1, 27 groups. Rows by source/label: {'audit|0': 116, 'audit|1': 236, 'corpus|0': 4567, 'fix_commit|0': 50, 'fix_commit|1': 54, 'incident|0': 11, 'incident|1': 13, 'mutation_original|0': 1080, 'mutation|1': 1539}. Checks passed before scoring: hashes, feature schema, no shared id / group / norm_hash with train.

PR-AUC 0.701 (weighted 0.635), ROC-AUC 0.784; ROC-AUC real label-1 vs contract-code corpus 0.547, mutations vs contract corpus 0.821, real vs paired fixed 0.489; pair rank (vulnerable > fixed) 89.5/172 = 52.0% [44.6%, 59.4%].

| | block | warn |
|---|---|---|
| recall, real label-1 (all) | 9/303 = 3.0% [1.6%, 5.5%] | 51/303 = 16.8% [13.0%, 21.5%] |
| recall, real label-1 severity != info | 9/215 = 4.2% [2.2%, 7.8%] | 41/215 = 19.1% [14.4%, 24.8%] |
| recall, real label-1 severity = info | 0/88 = 0.0% [0.0%, 4.2%] | 10/88 = 11.4% [6.3%, 19.7%] |
| time split (real label-1 dated >= 2025): recall | 5/129 = 3.9% [1.7%, 8.8%] | 17/129 = 13.2% [8.4%, 20.1%] |
| time split: recall, severity != info | 5/103 = 4.9% [2.1%, 10.9%] | 17/103 = 16.5% [10.6%, 24.9%] |
| recall, mutations | 654/1539 = 42.5% [40.0%, 45.0%] | 951/1539 = 61.8% [59.3%, 64.2%] |
| false alarms, corpus negatives (all) | 48/4567 = 1.1% [0.8%, 1.4%] | 236/4567 = 5.2% [4.6%, 5.8%] |
| false alarms, contract-code corpus negatives | 46/3699 = 1.2% [0.9%, 1.7%] | 218/3699 = 5.9% [5.2%, 6.7%] |
| false alarms, contract-code corpus excl. label conflicts | 46/3684 = 1.2% [0.9%, 1.7%] | 216/3684 = 5.9% [5.1%, 6.7%] |
| false alarms, paired fixed versions | 2/177 = 1.1% [0.3%, 4.0%] | 28/177 = 15.8% [11.2%, 21.9%] |
| false alarms, paired fixed excl. label conflicts | 2/170 = 1.2% [0.3%, 4.2%] | 28/170 = 16.5% [11.6%, 22.8%] |
| false alarms, mutation originals | 9/1080 = 0.8% [0.4%, 1.6%] | 99/1080 = 9.2% [7.6%, 11.0%] |
| contract level deployed rule: test corpus files holding no real label-1 alarming | 25/676 = 3.7% [2.5%, 5.4%] | 101/676 = 14.9% [12.5%, 17.8%] |
| contract level deployed rule: clean files alarming | n/a | n/a |
| contract level deployed rule: files holding a real vulnerability alarming | 16/161 = 9.9% [6.2%, 15.5%] | 55/161 = 34.2% [27.3%, 41.8%] |
| contract level protocol rule: clean files alarming | n/a | n/a |
| contract level protocol rule: files holding a real vulnerability alarming | 16/161 = 9.9% [6.2%, 15.5%] | 55/161 = 34.2% [27.3%, 41.8%] |

### Real label-1 recall by source

| | block | warn |
|---|---|---|
| audit | 8/236 = 3.4% [1.7%, 6.5%] | 44/236 = 18.6% [14.2%, 24.1%] |
| fix_commit | 1/54 = 1.9% [0.3%, 9.8%] | 5/54 = 9.3% [4.0%, 19.9%] |
| incident | 0/13 = 0.0% [0.0%, 22.8%] | 2/13 = 15.4% [4.3%, 42.2%] |

### Real label-1 (severity != info) recall by source

| | block | warn |
|---|---|---|
| audit | 8/148 = 5.4% [2.8%, 10.3%] | 34/148 = 23.0% [16.9%, 30.4%] |
| fix_commit | 1/54 = 1.9% [0.3%, 9.8%] | 5/54 = 9.3% [4.0%, 19.9%] |
| incident | 0/13 = 0.0% [0.0%, 22.8%] | 2/13 = 15.4% [4.3%, 42.2%] |

### Real label-1 recall by vuln_class

| | block | warn |
|---|---|---|
| None | 0/1 = 0.0% [0.0%, 79.3%] | 1/1 = 100.0% [20.7%, 100.0%] |
| async_reentrancy | 0/4 = 0.0% [0.0%, 49.0%] | 1/4 = 25.0% [4.6%, 69.9%] |
| ft_receiver_trust | 1/6 = 16.7% [3.0%, 56.4%] | 2/6 = 33.3% [9.7%, 70.0%] |
| gas_dos | 0/16 = 0.0% [0.0%, 19.4%] | 2/16 = 12.5% [3.5%, 36.0%] |
| logic_error | 2/120 = 1.7% [0.5%, 5.9%] | 14/120 = 11.7% [7.1%, 18.6%] |
| missing_access_control | 2/46 = 4.3% [1.2%, 14.5%] | 5/46 = 10.9% [4.7%, 23.0%] |
| missing_one_yocto | 0/10 = 0.0% [0.0%, 27.8%] | 1/10 = 10.0% [1.8%, 40.4%] |
| non_private_callback | 0/3 = 0.0% [0.0%, 56.2%] | 2/3 = 66.7% [20.8%, 93.9%] |
| oracle_price | 0/16 = 0.0% [0.0%, 19.4%] | 2/16 = 12.5% [3.5%, 36.0%] |
| precision_rounding | 1/13 = 7.7% [1.4%, 33.3%] | 3/13 = 23.1% [8.2%, 50.3%] |
| signer_auth | 1/3 = 33.3% [6.1%, 79.2%] | 1/3 = 33.3% [6.1%, 79.2%] |
| storage_staking | 0/21 = 0.0% [0.0%, 15.5%] | 5/21 = 23.8% [10.6%, 45.1%] |
| unchecked_receiver | 0/2 = 0.0% [0.0%, 65.8%] | 0/2 = 0.0% [0.0%, 65.8%] |
| unguarded_upgrade | 0/4 = 0.0% [0.0%, 49.0%] | 0/4 = 0.0% [0.0%, 49.0%] |
| unhandled_promise_result | 2/20 = 10.0% [2.8%, 30.1%] | 12/20 = 60.0% [38.7%, 78.1%] |
| unsafe_arithmetic | 0/18 = 0.0% [0.0%, 17.6%] | 0/18 = 0.0% [0.0%, 17.6%] |

### Real label-1 recall by severity

| | block | warn |
|---|---|---|
| None | 0/14 = 0.0% [0.0%, 21.5%] | 2/14 = 14.3% [4.0%, 39.9%] |
| critical | 0/8 = 0.0% [0.0%, 32.4%] | 1/8 = 12.5% [2.2%, 47.1%] |
| high | 2/54 = 3.7% [1.0%, 12.5%] | 12/54 = 22.2% [13.2%, 34.9%] |
| info | 0/88 = 0.0% [0.0%, 4.2%] | 10/88 = 11.4% [6.3%, 19.7%] |
| low | 2/60 = 3.3% [0.9%, 11.4%] | 10/60 = 16.7% [9.3%, 28.0%] |
| medium | 5/79 = 6.3% [2.7%, 14.0%] | 16/79 = 20.3% [12.9%, 30.4%] |

### Time split (>= 2025) recall by source

| | block | warn |
|---|---|---|
| audit | 4/87 = 4.6% [1.8%, 11.2%] | 11/87 = 12.6% [7.2%, 21.2%] |
| fix_commit | 1/37 = 2.7% [0.5%, 13.8%] | 4/37 = 10.8% [4.3%, 24.7%] |
| incident | 0/5 = 0.0% [0.0%, 43.4%] | 2/5 = 40.0% [11.8%, 76.9%] |

### Time split recall by vuln_class

| | block | warn |
|---|---|---|
| None | 0/1 = 0.0% [0.0%, 79.3%] | 1/1 = 100.0% [20.7%, 100.0%] |
| async_reentrancy | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| ft_receiver_trust | 0/2 = 0.0% [0.0%, 65.8%] | 1/2 = 50.0% [9.5%, 90.5%] |
| gas_dos | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] |
| logic_error | 0/38 = 0.0% [0.0%, 9.2%] | 2/38 = 5.3% [1.5%, 17.3%] |
| missing_access_control | 2/38 = 5.3% [1.5%, 17.3%] | 4/38 = 10.5% [4.2%, 24.1%] |
| missing_one_yocto | 0/6 = 0.0% [0.0%, 39.0%] | 0/6 = 0.0% [0.0%, 39.0%] |
| non_private_callback | 0/2 = 0.0% [0.0%, 65.8%] | 1/2 = 50.0% [9.5%, 90.5%] |
| oracle_price | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] |
| precision_rounding | 0/3 = 0.0% [0.0%, 56.2%] | 1/3 = 33.3% [6.1%, 79.2%] |
| signer_auth | 1/3 = 33.3% [6.1%, 79.2%] | 1/3 = 33.3% [6.1%, 79.2%] |
| storage_staking | 0/8 = 0.0% [0.0%, 32.4%] | 1/8 = 12.5% [2.2%, 47.1%] |
| unguarded_upgrade | 0/1 = 0.0% [0.0%, 79.3%] | 0/1 = 0.0% [0.0%, 79.3%] |
| unhandled_promise_result | 2/8 = 25.0% [7.1%, 59.1%] | 5/8 = 62.5% [30.6%, 86.3%] |
| unsafe_arithmetic | 0/6 = 0.0% [0.0%, 39.0%] | 0/6 = 0.0% [0.0%, 39.0%] |

### Time split recall by severity

| | block | warn |
|---|---|---|
| None | 0/6 = 0.0% [0.0%, 39.0%] | 2/6 = 33.3% [9.7%, 70.0%] |
| critical | 0/4 = 0.0% [0.0%, 49.0%] | 0/4 = 0.0% [0.0%, 49.0%] |
| high | 2/38 = 5.3% [1.5%, 17.3%] | 7/38 = 18.4% [9.2%, 33.4%] |
| info | 0/26 = 0.0% [0.0%, 12.9%] | 0/26 = 0.0% [0.0%, 12.9%] |
| low | 0/27 = 0.0% [0.0%, 12.5%] | 3/27 = 11.1% [3.9%, 28.1%] |
| medium | 3/28 = 10.7% [3.7%, 27.2%] | 5/28 = 17.9% [7.9%, 35.6%] |

### Mutation recall by vuln_class

| | block | warn |
|---|---|---|
| async_reentrancy | 0/10 = 0.0% [0.0%, 27.8%] | 2/10 = 20.0% [5.7%, 51.0%] |
| ft_receiver_trust | 0/15 = 0.0% [0.0%, 20.4%] | 9/15 = 60.0% [35.7%, 80.2%] |
| gas_dos | 5/52 = 9.6% [4.2%, 20.6%] | 17/52 = 32.7% [21.5%, 46.2%] |
| missing_access_control | 138/347 = 39.8% [34.8%, 45.0%] | 210/347 = 60.5% [55.3%, 65.5%] |
| missing_one_yocto | 50/215 = 23.3% [18.1%, 29.3%] | 110/215 = 51.2% [44.5%, 57.8%] |
| non_private_callback | 135/166 = 81.3% [74.7%, 86.5%] | 152/166 = 91.6% [86.3%, 94.9%] |
| oracle_price | 0/3 = 0.0% [0.0%, 56.2%] | 0/3 = 0.0% [0.0%, 56.2%] |
| precision_rounding | 38/88 = 43.2% [33.3%, 53.6%] | 68/88 = 77.3% [67.5%, 84.8%] |
| signer_auth | 242/300 = 80.7% [75.8%, 84.7%] | 263/300 = 87.7% [83.5%, 90.9%] |
| storage_staking | 1/85 = 1.2% [0.2%, 6.4%] | 13/85 = 15.3% [9.2%, 24.4%] |
| unchecked_receiver | 0/14 = 0.0% [0.0%, 21.5%] | 0/14 = 0.0% [0.0%, 21.5%] |
| unguarded_upgrade | 19/47 = 40.4% [27.6%, 54.7%] | 36/47 = 76.6% [62.8%, 86.4%] |
| unhandled_promise_result | 21/86 = 24.4% [16.6%, 34.5%] | 45/86 = 52.3% [41.9%, 62.6%] |
| unsafe_arithmetic | 5/111 = 4.5% [1.9%, 10.1%] | 26/111 = 23.4% [16.5%, 32.1%] |

### Held-out incidents (hacks)

| incident | date | class | vulnerable fns | max risk | outcome | fixed version alarms at |
|---|---|---|---|---|---|---|
| Aurora Engine ETH total supply depletion via SELFDESTRUCT (GHSA-3p69-m8gg-fwmf) | 2022-06-22 | logic_error | 1 | 0.576 | **missed** | missed |
| Aurora Engine deploy_upgrade callable by anyone | 2022-01-07 | unguarded_upgrade | 1 | 0.743 | **missed** | missed |
| Aurora Engine fee stealing in NEP-141 -> ERC-20 bridging | 2022-06-10 | ft_receiver_trust | 1 | 0.661 | **missed** | missed |
| Aurora Engine forged withdrawal receipts (Rainbow Bridge withdrawal logic error) | 2022-06-16 | logic_error | 1 | 0.471 | **missed** | missed |
| Aurora Engine infinite spend via DELEGATECALL to exit precompiles (ExitToEthereum) | 2022-04-26 | logic_error | 1 | 0.445 | **missed** | missed |
| Aurora Engine infinite spend via DELEGATECALL to exit precompiles (ExitToNear) | 2022-04-26 | logic_error | 1 | 0.432 | **missed** | missed |
| Aurora Engine relayer key manager could remove the engine's full-access key | 2024-11-11 | unhandled_promise_result | 1 | 0.304 | **missed** | missed |
| Aurora Engine silo admin methods open to anyone | 2025-08-08 | missing_access_control | 1 | 0.144 | **missed** | n/a |
| NEAR Intents deposit notification refunds not capped (ghost balances) | 2026-10-01 | unhandled_promise_result | 1 | 0.803 | **missed** | missed |
| NEAR Intents second deposit-notification vulnerability (bug bounty) | 2026-10-07 | None | 1 | 0.905 | **warn** | warn |
| Ref farming fake seed id in mft_on_transfer | 2021-08-09 | ft_receiver_trust | 1 | 0.637 | **missed** | missed |
| Rhea Finance margin trading slippage check double-counts reused swap outputs | 2026-04-16 | logic_error | 1 | 0.427 | **missed** | n/a |
| SWEAT token ft_resolve_transfer without #[private] | 2026-04-29 | non_private_callback | 1 | 0.873 | **warn** | missed |

vuln_class head on 302 real label-1 rows: accuracy 0.222, macro-F1 0.213.

Label conflicts (split audit `label_conflicts_j09.json`, test label-0 rows that are near-identical to a label-1 row): 29 rows in test.

Trivial functions (< 2 statements or body < 3 lines) are not scored by the deployed model and count as not alarming: {'incident|0': 1, 'audit|1': 29, 'audit|0': 3, 'fix_commit|1': 8, 'fix_commit|0': 2, 'mutation|1': 152, 'mutation_original|0': 95} test rows (source|label).

