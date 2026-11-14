# NEAR results log (sealed tests are scored once, numbers recorded as-is)

## Model choice and freeze (train only, before the sealed test was read), 2026-11-14
- Nested grouped CV on train_v1 (66,529 rows after the split audit's 396 leak drops), block = 1% / warn = 5% FPR on
  contract-code corpus functions. Real non-info recall at block: hgb 58/376 = 15.4% [12.1, 19.4], avg(hgb,logreg)
  48/376 = 12.8%, logreg 6.9%, UniXcoder encoder 4.5%; every encoder rank-ensemble lowered block recall (5.6-9.6%).
- Deployment check on 150 whole train-group repos found a length shortcut: the corpus negatives contain no trivial
  functions (< 2 statements or body < 3 lines; extract_corpus drops them), while 964 mutations are trivial, so the
  first freeze scored a one-line getter 0.71 and labelled 102/150 real repos `high`. Fix (decided on train only):
  trivial functions are not model-scored (detector hits only) and hgb is refit on non-trivial rows (65,069).
  Nested CV of that model, trivial rows counted as misses: block 49/376 = 13.0% [10.0, 16.8], warn 93/376 = 24.7%
  [20.6, 29.3]; hgb fit on all rows with the same exclusion: 44/376 = 11.7% / 95/376 = 25.3% (pre-declared rule:
  keep the non-trivial refit if its block recall is not lower). After the fix, 300 train-group repos: 26 high
  (8.7%), 104 medium (34.7%), 170 low (in-sample for their corpus functions, so optimistic).
- Frozen: near/models/frozen_near_v1.{pkl,json}, hgb (lr 0.1, 31 leaves, top 1000 chi2 tokens, info weight 0.3),
  thresholds block 0.6316 / warn 0.2908 from grouped 3-fold OOF scores, reload- and predict-path-verified.

## SEALED TEST v1 (NEAR code risk) — frozen `frozen_near_v1`, scored once 2026-11-14
- Model: hist gradient boosting (lr 0.1, 31 leaves, 300 iters, l2 1.0) on signed-log analyzer features + 1000 chi2-selected binary code-token 1-3 grams; trained on 65069 train_v1 rows (7728 label-1); thresholds block 0.6316 / warn 0.2908 = 1% / 5% FPR on contract-code corpus functions in training OOF scores; chosen over avg(hgb,logreg) and the UniXcoder encoder by nested-CV block recall on real vulnerabilities.
- Test: 7666 functions from 27 held-out repos; 1842 label-1.
- **Real vulnerabilities (severity != info): block 18/215 = 8.4% [5.4%, 12.8%], warn 42/215 = 19.5% [14.8%, 25.3%]**; all real 20/303 = 6.6% [4.3%, 10.0%] / 49/303 = 16.2% [12.5%, 20.7%]
- Time split (real, dated >= 2025): block 10/129 = 7.8% [4.3%, 13.7%], warn 22/129 = 17.1% [11.5%, 24.5%]
- Mutations: block 473/1539 = 30.7% [28.5%, 33.1%], warn 843/1539 = 54.8% [52.3%, 57.2%]
- False alarms, contract-code corpus functions: block 32/3699 = 0.9% [0.6%, 1.2%], warn 194/3699 = 5.2% [4.6%, 6.0%]; paired fixed versions: block 7/177 = 4.0% [1.9%, 7.9%], warn 22/177 = 12.4% [8.4%, 18.1%]
- Contract level (deployed rule): test corpus files holding no real label-1 alarm at block 15/676 = 2.2% [1.3%, 3.6%], warn 81/676 = 12.0% [9.7%, 14.6%]; files holding a real label-1 alarm at block 22/161 = 13.7% [9.2%, 19.8%], warn 56/161 = 34.8% [27.9%, 42.4%]
- Held-out hacks: 0 block, 3 warn, 10 missed of 13
- PR-AUC 0.671, ROC-AUC 0.786, real vs fixed ROC-AUC 0.475
- Details: near/model/reports/sealed_test_v1.md. After this scoring test_v1 is spent: the model is not changed on its basis; any later change needs a new sealed test.
- Notes: the per-group clean-file rate defined for CV is empty on test (every test group holds a real label-1
  row by construction), so the per-file rate above was added after the one scoring from the saved scores
  (`score_sealed --add-file-level`, no model run). Vulnerable vs fixed versions are ranked below chance (pair rank
  75.5/172 = 43.9% [36.7, 51.4]): the model scores code type, not the bug. Fix-commit rows are nearly missed
  (block 1/54). 8 Aurora Engine incidents scored <= 0.16. Severity-info rows (88) are reported separately.


## 2026-11-14 — frozen_near_v2 (NEAR code risk): ensemble of classical v2 + code LLM; test_v1c is DEVELOPMENT-INFORMED
- **What changed.** New training set train_v2 (split-audit drops, blind relabels, new fix-commit positives). Two v2
  models: classical v2 (`ctx_fixed_noera`: HGB on analyzer features computed with the function's file, per-detector
  counts, file / Cargo.toml context, code tokens; reports/classic_v2_cv.md) and a code LLM (Qwen2.5-Coder-0.5B,
  LoRA, pairwise loss; reports/llm_v2_cv.md). The frozen v2 is their mean-rank ensemble (risk = mean of each
  model's percentile against its held-out training scores). `near.model.predict` now serves v2 by default;
  `NEAR_ORACLE_MODEL=frozen_near_v1` serves v1. Code: near/model/freeze_v2.py (decide / freeze / score).
- **Decision (train_v2 OOF only, written before any test file was read;** near/models/frozen_near_v2.decision.md**).**
  Fixed rule: clean-contract-file alarm share at block <= 5%; then block recall on `confirmed` real vulnerabilities at
  pooled 1% contract-corpus FPR, a challenger needing a bootstrap-over-groups gain that excludes 0; then
  length-controlled pair rank; then latency. On 66,543 rows (177 confirmed): classical v2 10/177 = 5.6%, LLM 11/177
  = 6.2%, ensemble 15/177 = 8.5% (gain +2.8 pts [+0.5, +5.5]); all real 15 vs 22/451 (+1.6 pts [+0.3, +3.0]). The
  rule picked the ensemble. The gain is 5 functions and the interval barely clears 0. The ensemble is *worse* at
  warn: real recall -3.1 pts [-7.9, +2.5], confirmed -3.4 [-9.6, +3.3], mutations -3.7 [-5.0, -2.4]. Pair rank on
  the 52 real pairs whose vulnerable version is not shorter: classical 56.7%, LLM 57.7%, ensemble 62.5% [48.9,
  74.4]: all compatible with chance. "Shorter = riskier" alone ranks 83-88% of real pairs, so raw pair rank
  measures length.
- **Freeze** (near/models/frozen_near_v2.{pkl,json}). Classical part refit on all 65,093 non-trivial train_v2 rows
  with their file; its 3-fold OOF reproduces train_classic_v2's selection run exactly. LLM part = near/models/llm_final
  (trained on 4/5 of the groups), sha256-pinned in the manifest. Ensemble thresholds: block 0.9266 / warn 0.8504 (1% /
  5% FPR on contract-code corpus negatives) from the 13,081 rows of the 1/5 groups llm_final never trained on. The
  CV-pooled thresholds were 0.934 / 0.846. Reload and predict.py-path checks on 200 held-out rows: max |diff|
  5e-7. On those threshold rows the ensemble catches only 2/78 real positives at block and 9/78 at warn: a small
  sample, but no better than CV.
- **test_v1c, scored once 2026-11-14 06:57 UTC** (reports/test_v1c_v2.md). It is test_v1 with blind-cleaned labels.
  It is NOT sealed: test_v1's v1 results were seen before v2 was designed. Primary population = test rows whose source
  file is in the local clone (139 of 169 real positives), the same rule as training. v2 vs v1 on the same rows and
  labels:
  - block: real 6/139 = 4.3% vs 6/139 = 4.3% (diff +0.0 [-2.7, +3.4]); confirmed 6/107 vs 5/107; contract-corpus FPR
    1.2% vs 0.9%; clean files alarming 3.7% vs 2.1%; paired fixed versions alarming 0.9% vs 4.4%.
  - warn: real 29/139 = 20.9% vs 22/139 = 15.8% (+5.0 [-2.0, +11.8]); confirmed 24/107 = 22.4% vs 16.8%; FPR 5.9% vs 5.2%;
    clean files 15.2% vs 12.3%.
  - mutations: block 42.5% vs 30.7%; warn 61.8% vs 54.8%.
  - pair rank: 53.2% vs 47.7% on all real pairs; 6.5/14 vs 9.5/14 where the vulnerable version is not shorter.
  - held-out hacks: 0 block, 2 warn, 9 missed of 11 for v2; 0 block, 3 warn, 8 missed for v1.
  - All rows (v2 scores the 30 file-less positives from the function alone): block 9/169 = 5.3% vs **16/169 = 9.5%** for
    v1 (v1 catches 10 of the 30 file-less audit rows); warn 36/169 vs 36/169.
  - Original test_v1 labels, all rows: v1 reproduces sealed_test_v1 exactly (scores identical). v2: block 9/303 = 3.0%,
    warn 51/303 = 16.8%.
  - **No test difference between v2 and v1 is statistically distinguishable** (27 groups; every bootstrap interval
    includes 0).
- **Latency** (predict.score_source, LLM on counted functions only):
  - MPS: median crate (41 fns, 19 counted) 0.3 s; largest crate (485 fns, 105 counted) 1.6 s; 283-file repo (417
    counted) 5.3 s.
  - CPU: 3.4 s / 14.6 s / 57 s for the same three.
  - First call loads the 942 MB LLM in about 3 s.
- **Honest limits.**
  - v2 does not detect real vulnerabilities measurably better than v1. Its gains are on synthetic mutations and on
    fewer alarms on fixed versions.
  - No model sees the bug: length-controlled pair rank is at chance in CV and on test.
  - At freeze time the service fetched only `.rs` files, so the classical part saw no Cargo.toml (overflow-checks = -1,
    0.7% of training rows); near/service/source.py now also keeps Cargo.toml files. In-sample this lowers block alarms (contract FPR 0.4% -> 0.3%, real 64.7% -> 57.3%). The
    manifest's `held_out_rows_ensemble.manifest_missing_*` entry mixes an in-sample classical model with OOF thresholds
    and is not comparable.
  - LLM thresholds were fitted on MPS bf16 scores; CPU runs fp32 (same labels on the timing repos).
  - The LLM part is trained on 4/5 of the groups only.
  - Code hashes now pin context.py, train_classic_v2.py, encoder.py and llm_classifier.py: editing any of them makes v2
    refuse to load, and the service then falls back to detectors-only.

## 2026-11-14 — serving changes after the v2 freeze (no model or threshold change)
- Default model: `frozen_near_v2` when its LLM checkpoint (near/models/llm_final, ~0.9 GB) is unpacked, else
  `frozen_near_v1`; `NEAR_ORACLE_MODEL` overrides. A clone without the LLM archive serves v1, whose sealed test is above.
- Policy (near/service/policy.py): high code risk blocks only when a high-severity detector hit is on one of the
  high-risk functions; otherwise it warns. A public function too short for the model with a high-severity detector hit
  warns. Reason: at 1% function-level FPR, 2-4% of clean contract files alarm at block (sealed v1: 2.2%, test_v1c v2:
  3.7%), too many for a model-only block.
