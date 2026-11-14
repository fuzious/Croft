# Contract-code model: evidence

[Overview](../../../README.md) · [v1 raw results](sealed_test_v1.json) · [v2 comparison](test_v1c_v2.json)

**The code model is a supporting warning signal. Its score alone never blocks a payment.**

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
