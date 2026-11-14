# Contract-code model: evidence

[Overview](../../../README.md) · [v1 raw results](sealed_test_v1.json) · [v2 comparison](test_v1c_v2.json)

**Source analysis supports protocol investigation; it is separate from transaction classification. Its score alone is not proof of an exploitable contract.**

## Results

| Measure | v1 sealed test | v2 cleaned comparison |
|---|---:|---:|
| Real bugs flagged high | **18/215 · 8.4%** | **6/139 · 4.3%** |
| Real bugs flagged medium or high | 42/215 · 19.5% | 29/139 · 20.9% |
| Contract-function false alarms, high | 0.9% | 1.2% |
| Contract-function false alarms, medium+ | 5.2% | 5.9% |
| Held-out hacks, high / medium / missed | 0 / 3 / 10 | 0 / 2 / 9 |

**Different populations:** v1's real-bug rows exclude informational findings. The cleaned comparison uses 139
source-available functions; v1 also gets 6/139 high on those same rows. On all 303 original real-function labels,
v2 gets 9/303 = 3.0% high. Do not present these percentages as a controlled improvement.

No v2-versus-v1 test difference was statistically distinguishable across 27 repository groups. Ranking vulnerable
code above its own fix is at chance once code length is controlled. These models learn risky code patterns,
not reliable proof of a specific bug.

<details>
<summary>November 14 retraining: candidate rejected</summary>

Four fixed recipes tested real-bug weighting, fewer generated examples and stronger fixed-code negatives.
Formatting-duplicate repositories stayed together across fitting, calibration, selection and validation.

| Final development validation | Retrained baseline | Selected candidate |
|---|---:|---:|
| Real bugs, high | 2/107 | 4/107 |
| Real bugs, medium+ | 16/107 | 12/107 |
| Clean functions, high alerts | 78/9,177 | 97/9,177 |
| Fixed versions, high alerts | 0/101 | 3/101 |

The high-recall gain was **1.87 percentage points**, with a grouped 95% interval of **0 to 5.46 points**.
Warning recall fell. The candidate failed the predeclared acceptance checks; served weights are unchanged.
This compares two models fitted on the same training subset, **not** the deployed model or a fresh sealed test.
[Protocol, split hashes and measurements](training_candidate.json) · [Trainer](../train_candidate.py)

</details>

## Models and evaluation

| | v1 | v2 (optional) |
|---|---|---|
| Model | Gradient-boosted trees; Rust rules + code tokens | Classical context model + fine-tuned Qwen2.5-Coder-0.5B |
| Selection | Nested cross-validation grouped by repository | Training-only comparison and frozen decision rule |
| Test status | Frozen before sealed test | **Development-informed**: v1 results influenced v2's design |
| Availability | Default | Requires optional weights and `llm` dependencies |

Thresholds target 1% high and 5% medium false alarms on calibration/OOF contract functions, not whole contracts.
Clean contract files alarmed at high on 2.2% of the v1 test and 3.7% of the v2 comparison. Code-based blocking
therefore also requires a high-severity rule on the same high-risk function.

## Important qualifications

- Public-code pretraining may have seen older test repositories. Repository holdouts do not eliminate that risk.
- Trivial functions are not model-scored; rule checks still run. This exclusion was chosen on training data.
- v2's LLM trained on four-fifths of the training groups. Its final thresholds used the held-out fifth; only 78
  real positives were in that threshold slice, with 2 high detections.
- At freeze time the service lacked Cargo.toml context; it now supplies it. The reported service-context comparison
  is in-sample, not a new test. MPS thresholds were fitted with bf16; CPU uses fp32.
- NEP-330 source is receiver-controlled and is not matched to deployed WASM. A pinned source link still warns.

<details>
<summary>Training evidence and reproduction</summary>

Raw selection reports: [classical v1](classic_cv.json), [encoder](encoder_cv.json),
[classical v2](classic_v2_cv.json), [LLM v2](llm_v2_cv.json).
The first v1 freeze exposed a short-function shortcut on training repositories; excluding trivial functions and
refitting was decided before the sealed test. v2 used blind-cleaned labels, but its design followed v1 test results.

```bash
uv run python -m unittest near.model.test_predict near.model.test_freeze_v2
```

Artifacts are hash-pinned. Editing frozen feature/model code invalidates them. Sealed-test JSON and `.started`
markers intentionally remain: they prevent accidentally treating a used test as untouched. Generated Markdown
copies and console logs are omitted; the raw measurements remain above. A fresh accuracy claim needs fresh data.

</details>

<details>
<summary>Bug-type breakdown and sampled precision</summary>

Trained on 415 real NEAR bugs (250 audit findings, 163 fix commits, 2 incidents) plus 7,313 generated bug variants,
across 15 bug types. Scored once on a sealed test from 27 repositories held out of training (two have forks in
training).

| Bug type | Real training examples | Caught at high | Caught at medium or higher |
|---|---:|---:|---:|
| Logic error | 149 | 4 / 120 | 11 / 120 |
| Missing access control | 58 | 3 / 46 | 6 / 46 |
| Storage staking | 36 | 4 / 21 | 6 / 21 |
| Unhandled promise result | 35 | 4 / 20 | **12 / 20** |
| Async reentrancy | 23 | 0 / 4 | 1 / 4 |
| Gas denial of service | 21 | 1 / 16 | 3 / 16 |
| Unsafe arithmetic | 21 | 0 / 18 | 0 / 18 |
| Missing one-yocto check | 19 | 0 / 10 | 1 / 10 |
| Precision and rounding | 18 | 0 / 13 | 1 / 13 |
| Signer authentication | 11 | 1 / 3 | 1 / 3 |
| Non-private callback | 5 | 0 / 3 | 1 / 3 |
| Oracle price | 6 | 1 / 16 | 3 / 16 |
| Token receiver trust | 7 | 2 / 6 | 2 / 6 |
| Unchecked receiver | 5 | 0 / 2 | 0 / 2 |
| Unguarded upgrade | 1 | 0 / 4 | 0 / 4 |
| *Unclassified* | — | 0 / 1 | 1 / 1 |
| **All real bugs** | **415** | **20 / 303** | **49 / 303** |

| | High | Medium or higher |
|---|---|---|
| Recall, 303 real bugs | 20 / 303 = 6.6% | 49 / 303 = 16% |
| False alarms, 3,699 clean contract functions | 32 = 0.9% | 194 = 5.2% |
| Precision against clean contract functions (about 1 bug per 13) | 20 / 52 = 38% | 49 / 243 = 20% |
| Precision if 1 in 100 functions were buggy (estimate) | about 7% | about 3% |

Counting the fixed versions of the same bugs as false alarms too, precision is 34% at high and 18% at medium.

On 13 real security incidents it never saw (4 exploits, 4 bug bounties, 5 security fixes), it flagged 3 at medium
(both NEAR Intents deposit-notification bugs and the SWEAT callback without `#[private]`) and missed 10. One of
the 3 is also flagged on its fixed code. That is why a code score alone never blocks a payment.

</details>
