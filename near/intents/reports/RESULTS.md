# NEAR Intents transaction detector v1: results

Frozen model: `near/models/intents_v1.{pkl,json}` (IsolationForest on `tx_features`, plus the 12 invariant rules of
`near.intents.features`). All numbers come from `near/intents/reports/evaluation.json`, `paused_diagnostic.json` and
the freeze manifest, except where a paragraph says it was measured post hoc. Rates are k/n with Wilson 95% intervals.
Alerts per day use 97,000 Intents transactions a day (see "Alerts per day" for where that figure comes from).

## Bottom line

- The rules carry the detector. On every campaign the combined system flags exactly what rules alone flag, at medium
  and above. The anomaly model detected no attack that the rules missed.
- **Clean false-alarm estimate: the 7,400 collector-sampled test normals.** The other 5,063 test normals are scouting
  seeds that rule development measured false alarms on (Limits 4). On the collector rows, rules alone raise 0 alerts
  (0/7,400, Wilson upper bound 0.052%). The combined system raises 84/7,400 = 1.14% (0.92 to 1.40) at medium and 0
  at high; every one of the 84 comes from the anomaly model, and 80 of them came from one hour of incident response:
  deposits failing while `intents.near` was paused.
- **In practice `high` comes only from the high-severity rules.** The anomaly score never reached the high threshold
  on calibration, test or campaign data. (On the train months, the data it was fitted on, 1 of 69,863 normals does.)
- High alerts: the 23 exploit transactions of 2026-10-01 (all rule-driven; one technique repeated by one actor), and
  0 of 12,463 test normals.
- Alerts per day: about 39 medium alerts/day as a baseline, plus a burst whenever `intents.near` is paused (post-hoc
  split; see "Alerts per day").
- Attempt campaigns, per campaign: 96% of the April out-of-gas attempts (53/55), 62% of the May admin fuzzing
  (110/177) and 10% of the May token-spoof attempts (18/182) reach medium; 181/414 overall. All of these come from
  the rules; the anomaly model alone flags none of them.

## Setup

**Data.** 100,098 normal intents.near transactions (Nov 2024 to Nov 2026) and 570 labelled ones, from the collector.
No labelled transaction is used for training, model selection or thresholds.
- The normals pull did not run in one go. The operator stopped it at 84,149 records (SIGTERM, logged at
  2026-11-14T10:51:16Z; the collector finishes the current page and exits). The collector agent then resumed it,
  which appends to the same file, and it ended at its 100,000 target with 100,098 records (11:07:58Z). Both runs are
  in `near/data/intents/collect.log`. The model trains on all 100,098 (train slice below).
- 7,735 of the normals are scouting seeds (transactions pulled during scouting, around the exploit window and recent
  blocks); the rest come from random-start FastNEAR index pages of 200 consecutive transactions per month.

| slice | months | n | of which scouting seeds | use |
|---|---|---|---|---|
| train | 2024-11 to 2026-05 | 69,863 | 0 | fit the anomaly models (normals only) |
| calibration | 2026-06 to 2026-09 | 17,772 | 2,672 | model selection, thresholds |
| test (sealed) | 2026-10 to 2026-11 | 12,463 (7,763 + 4,700) | 5,063 | scored after the freeze |

By flow type (`features.flow_type`): train has 42,000 execute_intents, 22,170 deposit, 5,345 other and 348 withdrawal.
Calibration has 11,858 execute_intents, 5,687 deposit, 227 other and **0 withdrawal**. Test has 9,422 execute_intents,
2,912 deposit, 73 other and 56 withdrawal.

**Label.** `high` if a high-severity rule fires or the anomaly score reaches the high threshold; `medium` likewise
with medium rules and the medium threshold; otherwise `low`. Low rules (`execute_intents_panic`, `unknown_method`)
never raise the label. Displayed `risk` = max(rule weight, anomaly percentile against train normals); the weights
are high 1.0, medium 0.99908 (the percentile at the medium threshold) and low 0. Use `label` for decisions: an
ordinary failing execute_intents has risk around 0.96 and label `low`.

**Thresholds.** Taken on calibration normals so that the combined alert rate is at most 1/10,000 for high and at
most 1/1,000 for medium. Rule alerts use the budget first. On 17,772 rows the high budget is 1 alert, and one
calibration normal already fires a high rule (`log_limit`). So the anomaly high threshold sits above every
calibration score: 0.7353 (train percentile 0.999986). The medium threshold is 0.6766 (percentile 0.99908). On
calibration, 1 normal was high and 17 were medium or above (0.096%).

**Model selection (pre-declared in `model.DECISION_RULE`, one amendment disclosed).** There were two candidates:
- (A) a global IsolationForest on robust-standardized features;
- (B) a per-flow empirical tail model.

Rule (1) chooses the lower mean anomaly percentile on calibration normals that have a failed receipt, the known
normal failure mode. It picked B (0.935 against 0.966); that first run is kept in `freeze_first_pass.json`. That run
also showed a structural flaw in B: its highest attainable score is 3·log10((n_flow+1)/2), and this is below its own
medium threshold for deposit (12.134), other (10.28) and withdrawal (6.73). So B could only ever alert on
execute_intents. I then added eligibility condition (0): the score ceiling must reach the medium threshold in every
flow. Under it, A is the only eligible candidate. Neither run read an attack transaction or a test row. The rule
was still changed after seeing calibration output.

## Sealed test normals: false alarms

By source. The collector rows are the clean estimate; the scouting-seed rows were used in rule development
(Limits 4) and should not be read as out-of-sample for the rules.

| source | n | rules only, medium+ | anomaly only, medium+ | combined, medium+ | combined, high |
|---|---|---|---|---|---|
| **collector (clean)** | 7,400 | **0/7,400 (0 to 0.052%)** | 86/7,400 = 1.16% (0.94 to 1.43) | **84/7,400 = 1.14% (0.92 to 1.40)** | 0/7,400 (0 to 0.052%) |
| scouting seed | 5,063 | 0/5,063 (0 to 0.076%) | 1/5,063 = 0.020% (0.003 to 0.112) | 1/5,063 = 0.020% (0.003 to 0.112) | 0/5,063 (0 to 0.076%) |
| all | 12,463 | 0/12,463 (0 to 0.031%) | 87/12,463 = 0.70% (0.57 to 0.86) | 85/12,463 = 0.68% (0.55 to 0.84) | 0/12,463 (0 to 0.031%) |

All 99 paused-contract transactions of the test slice (see the diagnosis below) are collector rows, so the 80
paused-deposit alerts are all in the collector row. Excluding the paused-contract transactions, the collector rows
alert at 4/7,301 = 0.055% (0.021 to 0.141). That split is post hoc.

Combined, per flow type (all 12,463 rows):

| flow | medium or above |
|---|---|
| deposit | 80/2,912 = 2.75% (2.21 to 3.41) |
| execute_intents | 5/9,422 = 0.053% (0.023 to 0.124) |
| other | 0/73 (0 to 5.0%) |
| withdrawal | 0/56 (0 to 6.4%) |

Split by outcome, failing transactions alert at 81/2,740 = 2.96%, against 4/9,723 = 0.041% for successful ones.

**The medium target of 1/1,000 is missed on the test slice**, by more than tenfold on the clean collector rows.

Diagnosis (post hoc, `evaluate paused`; the model is unchanged): all 80 deposit alerts were in 2026-10-01 10:00 UTC.
They were BTC (77) and Zcash (3) bridge deposits whose `ft_on_transfer` on intents.near failed with "Pausable: Method
is paused", during the exploit response. The test slice has 99 such paused-contract transactions, and 80 of them
alert. Without them, the medium-or-above rate is 5/12,364 = 0.040% (0.017 to 0.095), within target. Arguably a
paused contract is a real anomaly, but it is not an attack. A deployment should either suppress alerts while the
contract is paused or show them as such.

**Alerts per day.** These come from the post-hoc paused split above, not from a pre-declared estimate.
- Baseline, outside paused periods: 5/12,364 × 97,000 ≈ **39 medium alerts/day** (17 to 92). On the collector rows
  alone it is 4/7,301 × 97,000 ≈ 53/day (21 to 137). High: 0/12,463, upper bound 30/day.
- Plus a burst whenever `intents.near` is paused: 80 of the 99 sampled paused-contract deposits alerted (81%). The
  99 come from consecutive collector pages within one hour, so this sample cannot tell how large a burst is in
  absolute terms; it scales with the deposit traffic during the pause.
- The pooled figure of 662/day in `evaluation.md` (85/12,463 × 97,000) mixes the two and is not a useful daily
  estimate: the paused hour dominates it.
- Where 97,000 comes from: it is the planning figure in `near/intents/PLAN.md` ("about 97k Intents transactions a
  day"). I could not trace it to a measurement in this repo or in the scouting notes. The collector's
  `near/data/intents/windows.json` (FastNEAR `txs_count` for intents.near per month) gives 2,692,047 / 31 = **86.8k
  per day for 2026-10** and 95.4k per day for 2026-09. At 86.8k/day the baseline would be about 35 medium alerts/day.

**Also below the target: rules alone over the training months.** Rules alone flag 327/69,863 = 0.47% (0.42 to 0.52)
of train-period normals at medium. Of these, 285 are `notify_receiver_in_deposit`, concentrated in 2025-04 to
2025-07 (234), which suggests legitimate Notify deposits in that period. The quiet calibration and test months
(0.02% and 0%) do not guarantee that rule false alarms stay low. Two normals outside the test slice fire a high rule:
- `failed_resolve_callback` on a 2025-07 deposit, `Bjfr1uwmhu1hvn4BM9aL3ztmpCp4gM72fkj2PguaC1fK`;
- `log_limit` on a 2026-08 execute_intents, `2j6RNcWu2NbzXnvUYV4vzcAzZgrfnenzyYFUHNnAa3mZ`.

I have not investigated either; they could be unlabelled attacks or benign edge cases.

**Where `high` comes from.** From `evaluation.json`: on calibration the one high is the `log_limit` rule hit above
(the anomaly high threshold sits above every calibration score by construction); on test there is no high; on the
campaigns all 23 highs are rule hits, and no campaign transaction reaches even the lower anomaly-only high threshold
(0.7147; the exploit's highest score is 0.6997). The only anomaly-driven high in any slice is 1 execute_intents
normal in the train months, which the model was fitted on. So in practice `high` means a high-severity rule fired.

## Campaign case studies (all held out from training and calibration)

| campaign / role | n | high / medium / missed | medium or above (95% CI) | rules that fired |
|---|---|---|---|---|
| 2026-10-01 exploit / exploit | 23 | 23 / 0 / 0 | 100% (85.7 to 100); effective sample is one campaign | failed_resolve_callback, log_limit, credit_kept (high) 23 each; many_token_ids, notify_receiver_in_deposit, refund_exceeds_deposit (medium) 23 each |
| 2026-10-01 exploit / setup | 14 | 0 / 0 / 14 | 0% (0 to 21.5) | none |
| 2026-10-01 exploit / cashout | 38 | 0 / 0 / 38 | 0% (0 to 9.2) | none |
| April out-of-gas attempts / attempt | 55 | 0 / 53 / 2 | 96.4% (87.7 to 99.0) | notify_receiver_in_deposit 51, callback_oog 8, return_value_limit 4 |
| April out-of-gas attempts / setup | 24 | 0 / 0 / 24 | 0% (0 to 13.8) | none |
| May token-spoof fuzzing / attempt | 182 | 0 / 18 / 164 | 9.9% (6.3 to 15.1) | private_method_direct 18, notify_receiver_in_deposit 1; execute_intents_panic (low) 113 |
| May token-spoof fuzzing / setup | 6 | 0 / 0 / 6 | 0% (0 to 39.0) | none |
| May admin-method fuzzing / attempt | 177 | 0 / 110 / 67 | 62.1% (54.8 to 69.0) | private_method_direct 82, admin_method_non_role (medium) 29; execute_intents_panic (low) 36 |
| May admin-method fuzzing / setup | 33 | 0 / 6 / 27 | 18.2% (8.6 to 34.4) | private_method_direct 6 |
| Rhea funding withdrawal (native_withdraw via execute_intents) | 1 | 0 / 0 / 1 | 0% (0 to 79.3) | none |
| team regression tests (negatives) | 17 | 0 / 12 / 5 | 70.6% (46.9 to 86.7) **false alarms** | private_method_direct 12, notify_receiver_in_deposit 4, refund_exceeds_deposit 4 |

Notes:
- **The 23/23 on the exploit is one technique repeated by one actor.** The Wilson interval treats the 23
  transactions as independent draws; they are not, and the effective sample is one campaign.
- **Setup, cashout and the Rhea funding withdrawal** are ordinary-shaped transactions by attacker accounts. A
  per-transaction detector cannot see them, and they are not counted as misses. Catching them needs account-level
  signals: the blocklist and counterparty checks of the oracle.
- **Team regression tests.** The team deliberately reproduced attack shapes on `staging-intents.near`: direct
  `mt_on_transfer` calls, and refunds larger than the deposit. 12 of 17 reach medium and none reach high. Those
  medium alerts are fair given the shapes, but they are false alarms.
- **Token-spoof attempts** mostly look like an ordinary failing `execute_intents`. The low `execute_intents_panic`
  rule also fires on about 20% of all test normals (2,572/12,463). Neither the rules nor the anomaly model separates
  them: their median anomaly percentile is 0.96, similar to the mean for failing calibration normals (0.966).

## Ablation (same rows, same thresholds procedure)

| | test normals medium+ | test normals high | exploit high | exploit medium+ | April attempts medium+ | May spoof medium+ | May admin medium+ | team tests medium+ |
|---|---|---|---|---|---|---|---|---|
| rules only | 0/12,463 | 0 | 23/23 | 23/23 | 53/55 | 18/182 | 110/177 | 12/17 |
| anomaly only (own thresholds) | 87/12,463 | 0 | 0/23 | 23/23 | 0/55 | 0/182 | 0/177 | 0/17 |
| anomaly only, 11 rule-mirroring features at train medians (post hoc) | not scored (sealed) | not scored | 0/23 | **0/23** | 0/55 | 0/182 | 0/177 | 0/17 |
| combined | 85/12,463 | 0 | 23/23 | 23/23 | 53/55 | 18/182 | 110/177 | 12/17 |

Without rules, the anomaly model catches the October exploit at medium only: 23/23, median percentile 0.9998, under
the high threshold. It catches nothing else. That one catch comes from features that mirror the rules. The third row
(measured post hoc, read-only, on the frozen intents_v1 with no refit and the frozen thresholds) sets 11 of the 63
features to their train-normal medians (the medians the model standardizes with) before scoring:
`credit_excess_log2`, `refund_to_sender_frac`, `refund_over_deposit_log10`, `n_failed_resolve`,
`n_notify_receivers`, `max_log_ratio`, `fail_log_limit`, `max_token_ids_per_event_log`, `max_dup_token_ids_log`,
`dust_fraction`, `amount_spread_log10`. The exploit's anomaly score then drops from 0.699 to 0.602 (percentile
0.9998 to 0.9894), and 0/23 exploit transactions reach medium under either the combined (0.6766) or the anomaly-only
(0.6722) medium threshold. No other campaign changes, since none reached medium on the anomaly score before. The
sealed test normals were not scored for this row.

On these numbers the anomaly model adds false alarms and no detections. I kept it in the deployed system as the
backstop for attack shapes that no rule encodes: its weights were fitted on normals only. But its feature set was
written with the October exploit in view, so it is not a blind detector either, and its value against unseen
attacks is **not demonstrated** by this evaluation.

## Limits and caveats

1. **Development-informed case studies.** The rules were written by the features owner after seeing the
   2026-10-01 exploit, whose transactions are test fixtures, and after measuring the April and May campaigns. So
   23/23 high on the exploit, and the April and May rule numbers, are not out-of-sample estimates. The anomaly
   model's weights never saw any campaign, but its feature set was written with the exploit in view: with the 11
   rule-mirroring features set to train-normal medians, 0/23 exploit transactions reach medium (scores 0.699 to
   0.602; see Ablation). Its 23/23 at medium is therefore not a blind detection either.
2. **Few campaigns.** There are about 5 actors and 4 attack campaigns. Intervals are wide, and per-campaign rates
   describe these actors, not attacks in general. The exploit's 23 transactions are one campaign.
3. **Model-selection amendment.** The selection rule was amended once after the calibration output (see Setup).
   The calibration slice was used for both selection and thresholds.
4. **Test slice composition.**
   - 5,063 of the 12,463 test normals (and 2,672 of the 17,772 calibration normals) are scouting seeds pulled around
     the exploit window and recent blocks. These 7,735 seeds were the rules' development set for false alarms: rule
     hits were measured on them and the rules iterated until `private_method_direct` went from 3 hits to 0 on them.
     6 of the 7 normal feature fixtures in `fixtures/features/` are test-slice (2026-10) rows. So the pooled test
     numbers are partly in-sample for the rules; the 7,400 collector rows are the clean estimate (rules only
     0/7,400, upper bound 0.052%; combined 84/7,400 = 1.14% at medium). The seeds also excluded only known attacker
     accounts, so unlabelled attacker traffic may remain.
   - The collector samples pages of 200 consecutive transactions, so samples come in bursts. The 80 paused-deposit
     alerts are one event. Wilson intervals assume independent samples and are therefore too narrow.
5. **Thin flows.**
   - Calibration has 0 withdrawals and 227 "other". Thresholds are effectively calibrated on execute_intents and
     deposit only.
   - Test intervals for withdrawal (56) and other (73) are 0 to 6% and 0 to 5%.
6. **Threshold resolution.**
   - With 17,772 calibration rows, the high threshold rests on a single rule alert. The 1/10,000 claim cannot be
     verified from these data.
   - On test, the high rate is 0/12,463, with an upper bound of 0.031%, or 30/day.
7. **The sealed test was scored twice for intents_v1, and the numbers did not change.**
   - First run: 11:16:07Z, manifest `bd47744e...`; kept as `evaluation_sealed_run1.json`.
   - After that run I corrected a garbled sentence in the `DECISION_RULE` string and wrapped long lines in
     `model.py`. That changed the code hash, so I refroze. The refreeze is seeded and gives the same model and
     thresholds.
   - Second run: `--rescore` at 11:17:25Z, manifest `4f7549c3...`. Its `evaluation.json` is identical to the first
     except for the hashes and timestamps; I checked this programmatically.
   - In addition, `head train` (the supervised head below) read the sealed test once for its own adoption decision.
     intents_v1 was unchanged by it.
   - The paused-contract diagnostic, the by-source split and the rule-mirroring ablation were all done after the
     sealed numbers were seen. The test was not scored again for them.
8. **intents_v1 uses no synthetic data**; a head trained on synthetic attacks was built and not adopted (below).
9. **An attacker-adjacent signer is in the train data.** 4 train normals (2026-05-19:
   `86CXYEB7...`, `GZBcPobe...`, `4rSV3FSh...`, `2CSogTcP...`) were signed by
   `f59f52d31ed269ade019a55ac4046a4e2fd7e0a3d6e585c4afc4777aab71f834`, a `setup` account in both May campaigns.
   `attacker_accounts.json` does not name it, so the collector kept them. Effect: 4 of 69,863 train rows; the model
   was not refrozen. The collector now also drops transactions signed by any signer of a labelled row whose role is
   not `team_regression_test`, except the infrastructure accounts that sign ordinary traffic (`intents.near`,
   `meteor-relayer.near`, `team.herewallet.near`). This applies to future pulls only; the bulk pull was not re-run.

## Reproduce

The frozen model and the small data files are in `archives/near_intents.zip` (Git LFS). From the repo root:

```bash
git lfs pull --include archives/near_intents.zip
unzip archives/near_intents.zip    # near/models/intents_v1.{pkl,json,train_ids.json},
                                   # near/data/intents/{labelled.jsonl.gz,stats.json,windows.json,
                                   #                    all_labelled_txs.jsonl}
```

That is enough for `score_tx` and `/v1/intents/score`: the artifact loads with its sha256 checks (pkl, train ids, and
the current `features.py` and `model.py`). The archive does not contain `normals.jsonl.gz` (239 MB), the feature cache
or synthetic data. The normals can be re-pulled with the collector, using the archived label file and the attacker
list in the test fixtures (the collector's defaults):

```bash
.venv/bin/python -m near.intents.collect normals
```

A re-pull does not reproduce the exact sample: FastNEAR pages are drawn afresh, the scouting's bulk seeds are not in
the archive, and the signer exclusion of Limits 9 now applies. With the normals in place:

**Warning:** on a re-pulled sample, `model freeze` overwrites the shipped `near/models/intents_v1.*`,
`evaluate run --rescore` overwrites the sealed `reports/evaluation.json` (and `evaluation.md`), and `evaluate paused`
overwrites `reports/paused_diagnostic.json`. To keep the shipped model and reports, skip those three lines, or back
up `near/models/intents_v1.*` and `near/intents/reports/` first.

```bash
.venv/bin/python -m unittest near.intents.test_model            # 19 tests, OK
.venv/bin/python -m near.intents.model cache                    # ~15 s: features + rules for 100,668 txs
.venv/bin/python -m near.intents.model freeze                   # ~3 s: fit, select, calibrate, freeze
.venv/bin/python -m near.intents.evaluate run --rescore         # ~5 s: refuses without --rescore (sealed)
.venv/bin/python -m near.intents.evaluate tables                # re-render evaluation.md from evaluation.json
.venv/bin/python -m near.intents.evaluate paused                # post-hoc paused-contract split
```

Predict API: `from near.intents.model import score_tx; score_tx(tx)` returns `{risk, label, rule_hits,
top_features, anomaly_score, anomaly_percentile, flow}`. It accepts FastNEAR or RPC transaction JSON. The artifact
loads with sha256 checks of the pkl, `features.py`, `model.py` and the train ids. One call takes about 5 ms.
`score_tx` agrees with the batch path on all 570 labelled transactions (0 mismatches).

## Optional supervised head on synthetic sandbox attacks: not adopted

`near/intents/head.py` (tests in `test_head.py`). Outputs: `reports/head_domain_check.json` and
`reports/head_evaluation.json`. The protocol (`head.PROTOCOL`) was written into the code before either stage ran. The
head never saw a real positive. **`intents_v1` and `score_tx` are unchanged; no `intents_v1_head` artifact was
written, and `model.py` was not edited.**

**Domain check (passed, narrowly).** A HistGradientBoosting classifier separated 992 synthetic benign sandbox txs
from 1,816 real normals from the train and calibration months (sampled to the same flow mix), with 5-fold
StratifiedGroupKFold (groups: sandbox family, real month):
- all 63 features: out-of-fold ROC-AUC 0.807 (fail, > 0.75);
- the pre-declared fix drops the most separating feature one at a time: `ev_nep141_ft_transfer` (0.810),
  `ev_nep245_mt_transfer` (0.751), `max_log_ratio` (**0.738**, pass).

0.738 passes the 0.75 bar but is not near chance. The sandbox benign traffic still differs from mainnet in event
mix, log counts, receipt depth and amount spread. The sandbox has no PoA `ft_mint`, no solver swaps, and its
receiver mix differs (see `synthetic/README.md`).

**Head.** Trained on the 60 kept features: 2,400 synthetic attacks against 992 synthetic benign plus 69,863 train
normals, with balanced class weights. Its thresholds were set on calibration normals, and intents_v1's alerts use
the budget first. The single high alert allowed in 17,772 calibration rows is already taken by a rule. So both head
thresholds land just above the highest calibration probability (0.1072). By construction, the head can only raise a
label to `high`, never to `medium`. Calibration alerts are unchanged: 1 high, 17 medium or above.

**Result (pre-declared adoption rule: at least 5 more real exploit/attempt txs at medium or above; at most 12 added
medium-or-above and at most 1 added high on test normals).** Applying this rule meant scoring the sealed test
normals once more, with the head (Limits 7).

| | intents_v1 | intents_v1 + head |
|---|---|---|
| real exploit + attempt txs (n=437), medium or above | 204 | 204 (gain 0) |
| real exploit + attempt txs, high | 23 | 201 |
| sealed test normals (n=12,463), medium or above | 85 | 85 |
| sealed test normals, high | 0 | **80** |
| team regression tests (negatives, n=17), high | 0 | 12 |

Decision: **not adopted**. There is no detection gain, and 80 test normals become high, against a limit of 1.
- The head's alerts on real campaigns are the same txs that the rules already flag at medium. It promotes them to
  high: April out-of-gas attempts 53, May admin fuzzing 107 of 110, May token spoof 18 of 18. It finds none of the
  164 token-spoof attempts or the 67 admin-fuzzing attempts that the rules miss.
- A post-hoc check (after the numbers) shows that all 80 test normals it raises to high are the BTC/Zcash deposits
  that failed with "Pausable: Method is paused" during the 2026-10-01 incident response. The head has learned
  roughly "a failing deposit is an attack", because almost every synthetic attack is a failing deposit. On mainnet
  that would have been 80 high false alarms in one hour.
- Synthetic attacks against the fixed verifier (v0.4.3 backport, never trained on) reach the head threshold in
  199 of 200 cases, and the 149 synthetic benign txs on that verifier in 1. So the head separates sandbox attacks
  from sandbox benign well. That separation does not carry over to new real detections.

Reproduce: `.venv/bin/python -m unittest near.intents.test_head` (9 tests),
`.venv/bin/python -m near.intents.head domain` (~20 s), `.venv/bin/python -m near.intents.head train` (~5 s).
