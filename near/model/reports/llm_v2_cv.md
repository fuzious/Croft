# Code LLM v2: nested grouped CV on train_v2 (Qwen/Qwen2.5-Coder-0.5B + LoRA r16, pairwise loss)

66590 of 66590 train_v2 rows scored out-of-fold (3 of 3 outer folds). Thresholds per fold from its inner validation fold (contract-code corpus negatives).

## Headline (pooled outer folds; nested thresholds except the mean-rank row)

| model | PR-AUC | ROC real vs contract corpus | ROC real vs its fixed | pair rank real (vuln > fixed) | pair rank mutation | real recall block | real recall warn | mutation recall warn | FPR contract corpus warn |
|---|---|---|---|---|---|---|---|---|---|
| llm (qwen05_cv3) | 0.567 | 0.584 | 0.579 | 280.0/408 = 68.6% [64.0%, 72.9%] | 8058.5/8181 = 98.5% [98.2%, 98.7%] | 19/498 = 3.8% [2.5%, 5.9%] | 68/498 = 13.7% [10.9%, 16.9%] | 4310/8275 = 52.1% [51.0%, 53.2%] | 2522/46647 = 5.4% [5.2%, 5.6%] |
| v1 HGB recipe (same folds/rows) | 0.646 | 0.690 | 0.579 | 224.5/408 = 55.0% [50.2%, 59.8%] | 7438.5/8181 = 90.9% [90.3%, 91.5%] | 31/498 = 6.2% [4.4%, 8.7%] | 92/498 = 18.5% [15.3%, 22.1%] | 4799/8275 = 58.0% [56.9%, 59.1%] | 2391/46647 = 5.1% [4.9%, 5.3%] |
| mean rank llm+hgb (pooled thresholds) | 0.655 | 0.652 | 0.586 | 256.0/408 = 62.7% [58.0%, 67.3%] | 7972.0/8181 = 97.4% [97.1%, 97.8%] | 23/498 = 4.6% [3.1%, 6.8%] | 74/498 = 14.9% [12.0%, 18.3%] | 4898/8275 = 59.2% [58.1%, 60.2%] | 2332/46647 = 5.0% [4.8%, 5.2%] |
| control: -len(code) (pooled thresholds) | 0.139 | 0.328 | 0.556 | 359.0/408 = 88.0% [84.5%, 90.8%] | 8097.0/8181 = 99.0% [98.7%, 99.2%] | 10/498 = 2.0% [1.1%, 3.7%] | 18/498 = 3.6% [2.3%, 5.6%] | 714/8275 = 8.6% [8.0%, 9.3%] | 2291/46647 = 4.9% [4.7%, 5.1%] |

### Reading the pair numbers

- A fix usually adds code. The control scorer 'shorter function = riskier' (no model) ranks 359.0/408 = 88.0% [84.5%, 90.8%] of real pairs and 8097.0/8181 = 99.0% [98.7%, 99.2%] of mutation pairs right, more than either model, so pair ranking alone does not show that a model sees the bug.
- On the real pairs where the vulnerable version is not shorter than its fix (n = 52), the LLM ranks 28.0/52 = 53.8% [40.5%, 66.7%] and the v1 HGB recipe 26.0/52 = 50.0% [36.9%, 63.1%]: both at chance. The LLM's gain over HGB comes from the pairs where the vulnerable version is shorter (252.0/356 = 70.8% [65.9%, 75.3%] vs 198.5/356 = 55.8% [50.6%, 60.8%]), which is what a 'missing check / missing code' cue would give. Mutation pairs (templated edits) are ranked right whatever their length.
- Against corpus code the LLM is not better than the v1 HGB recipe: real recall at warn 68/498 = 13.7% [10.9%, 16.9%] vs 92/498 = 18.5% [15.3%, 22.1%], PR-AUC 0.567 vs 0.646.
- On the validation folds, real pair ranking was higher after epoch 1 than after the last epoch in 3 of 3 folds (fold0, fold1, fold2), while the protocol's selection score (recall against corpus) preferred the last epoch: the second epoch traded pair signal for recall against corpus code.
- 'mean gap' below = mean of score(vulnerable) - score(fixed) over pairs (characters for the control).

## Protocol

- Rows: near/data/train_v2.jsonl (sha256 92b5f0d78415a2d9...), split-audit drops and blind relabels applied by assemble_v2; no test file read. Training rows: train_v2_small members of each inner-train split.
- Folds: near.model.encoder.fold_plan (3 outer GroupKFold folds over `group`, eval_common seed 20261114; validation = first inner group fold of the outer-train split, never trained on).
- Model: Qwen/Qwen2.5-Coder-0.5B, LoRA r 16 alpha 32 on q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj, score head trained; fp32 master weights, bf16 autocast on MPS; lr 0.0002, 2 epochs, <= 4096 padded tokens per batch, max length 512 (header whole, code head+tail), gradient checkpointing True.
- Loss: weighted BCE (eval_common.sample_weights: field `weight` = relabel/confidence weight; real label-1 total = mutation total) + 1.0 x margin-ranking (margin 1.0) over pairs whose two members share a batch (batches are built from whole pair units). Real pair weight 5.0 x the positive's weight; mutation pair weight 1. Corpus negatives subsampled to 30% per epoch (fresh draw each epoch, weight x 1/frac).
- Epoch kept by eval_common.selection_score on the validation fold; thresholds = 1% / 5% FPR on its contract-code corpus negatives.
- Baseline: the frozen v1 HGB recipe (params {"lr": 0.1, "leaves": 31, "svd": 0, "top_tokens": 1000}, same features as train_classic) fitted on the same training rows of the same folds, thresholds from the same validation fold.

## block (target FPR 1% on contract-code corpus negatives)

| population | llm (qwen05_cv3) | v1 HGB recipe (same folds/rows) | mean rank llm+hgb (pooled thresholds) | control: -len(code) (pooled thresholds) |
|---|---|---|---|---|
| recall real label-1 | 19/498 = 3.8% [2.5%, 5.9%] | 31/498 = 6.2% [4.4%, 8.7%] | 23/498 = 4.6% [3.1%, 6.8%] | 10/498 = 2.0% [1.1%, 3.7%] |
| recall mutation | 1973/8275 = 23.8% [22.9%, 24.8%] | 2856/8275 = 34.5% [33.5%, 35.5%] | 2867/8275 = 34.6% [33.6%, 35.7%] | 328/8275 = 4.0% [3.6%, 4.4%] |
| FPR corpus (all) | 478/51410 = 0.9% [0.9%, 1.0%] | 449/51410 = 0.9% [0.8%, 1.0%] | 484/51410 = 0.9% [0.9%, 1.0%] | 585/51410 = 1.1% [1.0%, 1.2%] |
| FPR corpus, contract code | 463/46647 = 1.0% [0.9%, 1.1%] | 435/46647 = 0.9% [0.8%, 1.0%] | 466/46647 = 1.0% [0.9%, 1.1%] | 454/46647 = 1.0% [0.9%, 1.1%] |
| FPR real fixed versions | 3/421 = 0.7% [0.2%, 2.1%] | 6/421 = 1.4% [0.7%, 3.1%] | 4/421 = 1.0% [0.4%, 2.4%] | 3/421 = 0.7% [0.2%, 2.1%] |
| FPR mutation originals | 17/5986 = 0.3% [0.2%, 0.5%] | 55/5986 = 0.9% [0.7%, 1.2%] | 38/5986 = 0.6% [0.5%, 0.9%] | 104/5986 = 1.7% [1.4%, 2.1%] |
| contract files alarming (clean groups) | 264/6027 = 4.4% [3.9%, 4.9%] | 249/6027 = 4.1% [3.7%, 4.7%] | 269/6027 = 4.5% [4.0%, 5.0%] | 203/6027 = 3.4% [2.9%, 3.9%] |
| files holding a real label-1 fn alarming | 29/285 = 10.2% [7.2%, 14.2%] | 36/285 = 12.6% [9.3%, 17.0%] | 34/285 = 11.9% [8.7%, 16.2%] | 20/285 = 7.0% [4.6%, 10.6%] |
| recall real, verdict=confirmed | 15/199 = 7.5% [4.6%, 12.1%] | 22/199 = 11.1% [7.4%, 16.2%] | 16/199 = 8.0% [5.0%, 12.7%] | 3/199 = 1.5% [0.5%, 4.3%] |
| recall real, verdict=plausible | 1/90 = 1.1% [0.2%, 6.0%] | 3/90 = 3.3% [1.1%, 9.3%] | 2/90 = 2.2% [0.6%, 7.7%] | 1/90 = 1.1% [0.2%, 6.0%] |
| recall real, verdict=none | 3/209 = 1.4% [0.5%, 4.1%] | 6/209 = 2.9% [1.3%, 6.1%] | 5/209 = 2.4% [1.0%, 5.5%] | 6/209 = 2.9% [1.3%, 6.1%] |
| recall real, source=audit | 8/144 = 5.6% [2.8%, 10.6%] | 13/144 = 9.0% [5.4%, 14.8%] | 7/144 = 4.9% [2.4%, 9.7%] | 3/144 = 2.1% [0.7%, 5.9%] |
| recall real, source=incident | 0/2 = 0.0% [0.0%, 65.8%] | 0/2 = 0.0% [0.0%, 65.8%] | 0/2 = 0.0% [0.0%, 65.8%] | 0/2 = 0.0% [0.0%, 65.8%] |
| recall real, source=fix_commit | 11/352 = 3.1% [1.8%, 5.5%] | 18/352 = 5.1% [3.3%, 7.9%] | 16/352 = 4.5% [2.8%, 7.3%] | 7/352 = 2.0% [1.0%, 4.0%] |
| recall real, class async_reentrancy | 0/42 = 0.0% [0.0%, 8.4%] | 2/42 = 4.8% [1.3%, 15.8%] | 0/42 = 0.0% [0.0%, 8.4%] | 0/42 = 0.0% [0.0%, 8.4%] |
| recall real, class ft_receiver_trust | 0/4 = 0.0% [0.0%, 49.0%] | 0/4 = 0.0% [0.0%, 49.0%] | 0/4 = 0.0% [0.0%, 49.0%] | 0/4 = 0.0% [0.0%, 49.0%] |
| recall real, class gas_dos | 1/15 = 6.7% [1.2%, 29.8%] | 1/15 = 6.7% [1.2%, 29.8%] | 1/15 = 6.7% [1.2%, 29.8%] | 0/15 = 0.0% [0.0%, 20.4%] |
| recall real, class logic_error | 3/149 = 2.0% [0.7%, 5.8%] | 3/149 = 2.0% [0.7%, 5.8%] | 2/149 = 1.3% [0.4%, 4.8%] | 1/149 = 0.7% [0.1%, 3.7%] |
| recall real, class missing_access_control | 1/52 = 1.9% [0.3%, 10.1%] | 5/52 = 9.6% [4.2%, 20.6%] | 2/52 = 3.8% [1.1%, 13.0%] | 2/52 = 3.8% [1.1%, 13.0%] |
| recall real, class missing_one_yocto | 1/47 = 2.1% [0.4%, 11.1%] | 1/47 = 2.1% [0.4%, 11.1%] | 1/47 = 2.1% [0.4%, 11.1%] | 4/47 = 8.5% [3.4%, 19.9%] |
| recall real, class non_private_callback | 3/7 = 42.9% [15.8%, 75.0%] | 5/7 = 71.4% [35.9%, 91.8%] | 5/7 = 71.4% [35.9%, 91.8%] | 0/7 = 0.0% [0.0%, 35.4%] |
| recall real, class oracle_price | 0/7 = 0.0% [0.0%, 35.4%] | 0/7 = 0.0% [0.0%, 35.4%] | 0/7 = 0.0% [0.0%, 35.4%] | 0/7 = 0.0% [0.0%, 35.4%] |
| recall real, class precision_rounding | 2/19 = 10.5% [2.9%, 31.4%] | 1/19 = 5.3% [0.9%, 24.6%] | 3/19 = 15.8% [5.5%, 37.6%] | 0/19 = 0.0% [0.0%, 16.8%] |
| recall real, class signer_auth | 3/13 = 23.1% [8.2%, 50.3%] | 6/13 = 46.2% [23.2%, 70.9%] | 6/13 = 46.2% [23.2%, 70.9%] | 1/13 = 7.7% [1.4%, 33.3%] |
| recall real, class storage_staking | 0/50 = 0.0% [0.0%, 7.1%] | 3/50 = 6.0% [2.1%, 16.2%] | 1/50 = 2.0% [0.4%, 10.5%] | 1/50 = 2.0% [0.4%, 10.5%] |
| recall real, class unchecked_receiver | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] |
| recall real, class unguarded_upgrade | 0/8 = 0.0% [0.0%, 32.4%] | 2/8 = 25.0% [7.1%, 59.1%] | 1/8 = 12.5% [2.2%, 47.1%] | 0/8 = 0.0% [0.0%, 32.4%] |
| recall real, class unhandled_promise_result | 5/67 = 7.5% [3.2%, 16.3%] | 2/67 = 3.0% [0.8%, 10.2%] | 1/67 = 1.5% [0.3%, 8.0%] | 1/67 = 1.5% [0.3%, 8.0%] |
| recall real, class unsafe_arithmetic | 0/13 = 0.0% [0.0%, 22.8%] | 0/13 = 0.0% [0.0%, 22.8%] | 0/13 = 0.0% [0.0%, 22.8%] | 0/13 = 0.0% [0.0%, 22.8%] |

## warn (target FPR 5% on contract-code corpus negatives)

| population | llm (qwen05_cv3) | v1 HGB recipe (same folds/rows) | mean rank llm+hgb (pooled thresholds) | control: -len(code) (pooled thresholds) |
|---|---|---|---|---|
| recall real label-1 | 68/498 = 13.7% [10.9%, 16.9%] | 92/498 = 18.5% [15.3%, 22.1%] | 74/498 = 14.9% [12.0%, 18.3%] | 18/498 = 3.6% [2.3%, 5.6%] |
| recall mutation | 4310/8275 = 52.1% [51.0%, 53.2%] | 4799/8275 = 58.0% [56.9%, 59.1%] | 4898/8275 = 59.2% [58.1%, 60.2%] | 714/8275 = 8.6% [8.0%, 9.3%] |
| FPR corpus (all) | 2609/51410 = 5.1% [4.9%, 5.3%] | 2470/51410 = 4.8% [4.6%, 5.0%] | 2419/51410 = 4.7% [4.5%, 4.9%] | 2772/51410 = 5.4% [5.2%, 5.6%] |
| FPR corpus, contract code | 2522/46647 = 5.4% [5.2%, 5.6%] | 2391/46647 = 5.1% [4.9%, 5.3%] | 2332/46647 = 5.0% [4.8%, 5.2%] | 2291/46647 = 4.9% [4.7%, 5.1%] |
| FPR real fixed versions | 21/421 = 5.0% [3.3%, 7.5%] | 32/421 = 7.6% [5.4%, 10.5%] | 25/421 = 5.9% [4.1%, 8.6%] | 10/421 = 2.4% [1.3%, 4.3%] |
| FPR mutation originals | 188/5986 = 3.1% [2.7%, 3.6%] | 367/5986 = 6.1% [5.6%, 6.8%] | 241/5986 = 4.0% [3.6%, 4.6%] | 384/5986 = 6.4% [5.8%, 7.1%] |
| contract files alarming (clean groups) | 1099/6027 = 18.2% [17.3%, 19.2%] | 1158/6027 = 19.2% [18.2%, 20.2%] | 1112/6027 = 18.5% [17.5%, 19.4%] | 830/6027 = 13.8% [12.9%, 14.7%] |
| files holding a real label-1 fn alarming | 97/285 = 34.0% [28.8%, 39.7%] | 119/285 = 41.8% [36.2%, 47.6%] | 101/285 = 35.4% [30.1%, 41.2%] | 42/285 = 14.7% [11.1%, 19.3%] |
| recall real, verdict=confirmed | 35/199 = 17.6% [12.9%, 23.5%] | 53/199 = 26.6% [21.0%, 33.2%] | 41/199 = 20.6% [15.6%, 26.8%] | 8/199 = 4.0% [2.1%, 7.7%] |
| recall real, verdict=plausible | 12/90 = 13.3% [7.8%, 21.9%] | 22/90 = 24.4% [16.7%, 34.2%] | 14/90 = 15.6% [9.5%, 24.4%] | 2/90 = 2.2% [0.6%, 7.7%] |
| recall real, verdict=none | 21/209 = 10.0% [6.7%, 14.9%] | 17/209 = 8.1% [5.1%, 12.6%] | 19/209 = 9.1% [5.9%, 13.8%] | 8/209 = 3.8% [2.0%, 7.4%] |
| recall real, source=audit | 22/144 = 15.3% [10.3%, 22.0%] | 45/144 = 31.2% [24.2%, 39.2%] | 28/144 = 19.4% [13.8%, 26.7%] | 6/144 = 4.2% [1.9%, 8.8%] |
| recall real, source=incident | 0/2 = 0.0% [0.0%, 65.8%] | 0/2 = 0.0% [0.0%, 65.8%] | 0/2 = 0.0% [0.0%, 65.8%] | 0/2 = 0.0% [0.0%, 65.8%] |
| recall real, source=fix_commit | 46/352 = 13.1% [9.9%, 17.0%] | 47/352 = 13.4% [10.2%, 17.3%] | 46/352 = 13.1% [9.9%, 17.0%] | 12/352 = 3.4% [2.0%, 5.9%] |
| recall real, class async_reentrancy | 2/42 = 4.8% [1.3%, 15.8%] | 4/42 = 9.5% [3.8%, 22.1%] | 3/42 = 7.1% [2.5%, 19.0%] | 0/42 = 0.0% [0.0%, 8.4%] |
| recall real, class ft_receiver_trust | 1/4 = 25.0% [4.6%, 69.9%] | 0/4 = 0.0% [0.0%, 49.0%] | 0/4 = 0.0% [0.0%, 49.0%] | 0/4 = 0.0% [0.0%, 49.0%] |
| recall real, class gas_dos | 3/15 = 20.0% [7.0%, 45.2%] | 4/15 = 26.7% [10.9%, 52.0%] | 4/15 = 26.7% [10.9%, 52.0%] | 0/15 = 0.0% [0.0%, 20.4%] |
| recall real, class logic_error | 13/149 = 8.7% [5.2%, 14.4%] | 16/149 = 10.7% [6.7%, 16.7%] | 13/149 = 8.7% [5.2%, 14.4%] | 3/149 = 2.0% [0.7%, 5.8%] |
| recall real, class missing_access_control | 9/52 = 17.3% [9.4%, 29.7%] | 14/52 = 26.9% [16.8%, 40.3%] | 11/52 = 21.2% [12.2%, 34.0%] | 3/52 = 5.8% [2.0%, 15.6%] |
| recall real, class missing_one_yocto | 2/47 = 4.3% [1.2%, 14.2%] | 1/47 = 2.1% [0.4%, 11.1%] | 2/47 = 4.3% [1.2%, 14.2%] | 7/47 = 14.9% [7.4%, 27.7%] |
| recall real, class non_private_callback | 6/7 = 85.7% [48.7%, 97.4%] | 7/7 = 100.0% [64.6%, 100.0%] | 7/7 = 100.0% [64.6%, 100.0%] | 0/7 = 0.0% [0.0%, 35.4%] |
| recall real, class oracle_price | 1/7 = 14.3% [2.6%, 51.3%] | 2/7 = 28.6% [8.2%, 64.1%] | 0/7 = 0.0% [0.0%, 35.4%] | 0/7 = 0.0% [0.0%, 35.4%] |
| recall real, class precision_rounding | 4/19 = 21.1% [8.5%, 43.3%] | 6/19 = 31.6% [15.4%, 54.0%] | 4/19 = 21.1% [8.5%, 43.3%] | 1/19 = 5.3% [0.9%, 24.6%] |
| recall real, class signer_auth | 8/13 = 61.5% [35.5%, 82.3%] | 11/13 = 84.6% [57.8%, 95.7%] | 9/13 = 69.2% [42.4%, 87.3%] | 1/13 = 7.7% [1.4%, 33.3%] |
| recall real, class storage_staking | 6/50 = 12.0% [5.6%, 23.8%] | 11/50 = 22.0% [12.8%, 35.2%] | 7/50 = 14.0% [7.0%, 26.2%] | 1/50 = 2.0% [0.4%, 10.5%] |
| recall real, class unchecked_receiver | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] | 0/5 = 0.0% [0.0%, 43.4%] |
| recall real, class unguarded_upgrade | 2/8 = 25.0% [7.1%, 59.1%] | 4/8 = 50.0% [21.5%, 78.5%] | 3/8 = 37.5% [13.7%, 69.4%] | 0/8 = 0.0% [0.0%, 32.4%] |
| recall real, class unhandled_promise_result | 9/67 = 13.4% [7.2%, 23.6%] | 11/67 = 16.4% [9.4%, 27.1%] | 10/67 = 14.9% [8.3%, 25.3%] | 1/67 = 1.5% [0.3%, 8.0%] |
| recall real, class unsafe_arithmetic | 2/13 = 15.4% [4.3%, 42.2%] | 1/13 = 7.7% [1.4%, 33.3%] | 1/13 = 7.7% [1.4%, 33.3%] | 1/13 = 7.7% [1.4%, 33.3%] |

## Real (vulnerable, fixed) pairs in detail

| subset | llm (qwen05_cv3) rank acc | mean gap | v1 HGB recipe (same folds/rows) rank acc | mean gap | mean rank llm+hgb (pooled thresholds) rank acc | mean gap | control: -len(code) (pooled thresholds) rank acc | mean gap |
|---|---|---|---|---|---|---|---|---|
| all | 280.0/408 = 68.6% [64.0%, 72.9%] | +0.075 | 224.5/408 = 55.0% [50.2%, 59.8%] | +0.043 | 256.0/408 = 62.7% [58.0%, 67.3%] | +0.055 | 359.0/408 = 88.0% [84.5%, 90.8%] | +157.676 |
| len=vuln same or longer | 28.0/52 = 53.8% [40.5%, 66.7%] | +0.046 | 26.0/52 = 50.0% [36.9%, 63.1%] | +0.034 | 31.0/52 = 59.6% [46.1%, 71.8%] | +0.022 | 3.0/52 = 5.8% [2.0%, 15.6%] | -108.481 |
| len=vuln shorter | 252.0/356 = 70.8% [65.9%, 75.3%] | +0.079 | 198.5/356 = 55.8% [50.6%, 60.8%] | +0.044 | 225.0/356 = 63.2% [58.1%, 68.0%] | +0.060 | 356.0/356 = 100.0% [98.9%, 100.0%] | +196.553 |
| source=audit | 39.0/64 = 60.9% [48.7%, 71.9%] | +0.056 | 30.5/64 = 47.7% [35.9%, 59.7%] | +0.001 | 36.0/64 = 56.2% [44.1%, 67.7%] | +0.000 | 52.5/64 = 82.0% [70.9%, 89.5%] | +157.188 |
| source=fix_commit | 240.0/343 = 70.0% [64.9%, 74.6%] | +0.079 | 193.0/343 = 56.3% [51.0%, 61.4%] | +0.051 | 219.0/343 = 63.8% [58.6%, 68.8%] | +0.065 | 305.5/343 = 89.1% [85.3%, 91.9%] | +158.070 |
| source=incident | 1.0/1 = 100.0% [20.7%, 100.0%] | +0.166 | 1.0/1 = 100.0% [20.7%, 100.0%] | +0.036 | 1.0/1 = 100.0% [20.7%, 100.0%] | +0.121 | 1.0/1 = 100.0% [20.7%, 100.0%] | +54.000 |
| verdict=confirmed | 101.5/154 = 65.9% [58.1%, 72.9%] | +0.118 | 81.5/154 = 52.9% [45.1%, 60.6%] | +0.075 | 91.0/154 = 59.1% [51.2%, 66.5%] | +0.064 | 135.5/154 = 88.0% [81.9%, 92.2%] | +152.740 |
| verdict=none (v2 fix commit) | 143.5/205 = 70.0% [63.4%, 75.9%] | +0.045 | 112.0/205 = 54.6% [47.8%, 61.3%] | +0.028 | 133.0/205 = 64.9% [58.1%, 71.1%] | +0.050 | 185.5/205 = 90.5% [85.7%, 93.8%] | +171.810 |
| verdict=plausible | 35.0/49 = 71.4% [57.6%, 82.2%] | +0.065 | 31.0/49 = 63.3% [49.3%, 75.3%] | +0.004 | 32.0/49 = 65.3% [51.3%, 77.1%] | +0.048 | 38.0/49 = 77.6% [64.1%, 87.0%] | +114.061 |

Mutation (mutant, original) pairs by length: llm (qwen05_cv3): len=vuln shorter 7904.0/8020 = 98.6% [98.3%, 98.8%], len=vuln same or longer 154.5/161 = 96.0% [91.7%, 98.1%]; v1 HGB recipe (same folds/rows): len=vuln shorter 7288.0/8020 = 90.9% [90.2%, 91.5%], len=vuln same or longer 150.5/161 = 93.5% [88.6%, 96.4%]; mean rank llm+hgb (pooled thresholds): len=vuln shorter 7816.0/8020 = 97.5% [97.1%, 97.8%], len=vuln same or longer 156.0/161 = 96.9% [92.9%, 98.7%]; control: -len(code) (pooled thresholds): len=vuln shorter 8020.0/8020 = 100.0% [100.0%, 100.0%], len=vuln same or longer 77.0/161 = 47.8% [40.3%, 55.5%]

## Folds

| fold | train | val | test | real pairs | mutation pairs | best epoch | seconds | history |
|---|---|---|---|---|---|---|---|---|
| fold0 | 27154 | 14798 | 22197 | 203 | 4256 | 2 | 2644 | e1 sel 0.200 prauc 0.407 pair-real 0.654 pair-mut 0.990; e2 sel 0.245 prauc 0.506 pair-real 0.603 pair-mut 0.990 |
| fold1 | 26866 | 14798 | 22197 | 201 | 3599 | 2 | 2274 | e1 sel 0.179 prauc 0.441 pair-real 0.728 pair-mut 0.975; e2 sel 0.278 prauc 0.592 pair-real 0.691 pair-mut 0.979 |
| fold2 | 26819 | 14798 | 22196 | 192 | 3781 | 2 | 2269 | e1 sel 0.138 prauc 0.411 pair-real 0.789 pair-mut 0.984; e2 sel 0.221 prauc 0.547 pair-real 0.627 pair-mut 0.985 |

## Deployable merged model `near/models/llm_final`

LoRA merged into the base weights, saved bf16 as a plain transformers Qwen2ForSequenceClassification (load with near.model.llm_classifier.load_final, no peft). Trained on 47837 train_v2_small rows of 4/5 of the groups (group_folds(rows, 5, SEED + 99)[0]); epoch and thresholds from the other 1/5 (13318 train_v2 rows, never trained on): best epoch 2, block 0.9161, warn 0.7098. Merge parity on 512 validation rows: max |diff| 0.0206, Spearman 0.9999.
Validation history: e1 sel 0.176 PR-AUC 0.474 pair-real 0.720; e2 sel 0.230 PR-AUC 0.600 pair-real 0.693

## Inference latency per function (merged model)

```
{
 "n": 200,
 "prep_ms_per_fn": 0.6662452220916748,
 "mps_batch1_ms_per_fn": 19.41930890083313,
 "mps_batched_ms_per_fn": 6.645795106887817,
 "mps_dtype": "torch.bfloat16",
 "cpu_batch1_ms_per_fn": 171.49526278177896,
 "cpu_batched_ms_per_fn": 133.21425120035806,
 "cpu_dtype": "torch.float32",
 "threads_cpu": 6
}
```

OOF scores: near/models/llm_oof.jsonl (sha256 56845c05269d125f...).
