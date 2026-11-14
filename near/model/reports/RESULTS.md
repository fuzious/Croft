# Source-model evidence

Source scores identify risky code patterns, not proof of an exploitable contract. Raw JSON and `.started` markers retain measurements and test history.

| Evidence | Report |
|---|---|
| Frozen v1 sealed test and bug-type breakdown | [sealed_test_v1.json](sealed_test_v1.json) |
| Development-informed v2 comparison | [test_v1c_v2.json](test_v1c_v2.json) |
| Rejected November 14 retraining | [training_candidate.json](training_candidate.json) |
| Selection | [classic_cv.json](classic_cv.json), [encoder_cv.json](encoder_cv.json), [classic_v2_cv.json](classic_v2_cv.json), [llm_v2_cv.json](llm_v2_cv.json) |

v1 flags 18/215 non-informational real bugs high (8.4%), 42/215 medium+ (19.5%); clean-function false alarms are 0.9% high, 5.2% medium+.
Across all 303 original real-function labels: 20 high, 49 medium+; 3/13 held-out incidents are medium and 10 missed (one detected incident also flags its fix).
v2's source-available comparison flags 6/139 high, 29/139 medium+; false alarms are 1.2% high, 5.9% medium+.
v1 also flags 6/139 high on those same rows; v2 flags 9/303 high over all original labels. These different populations are not a controlled improvement.
No v1/v2 difference was statistically distinguishable across 27 repository groups; ranking bugs above their fixes is at chance after controlling code length.

The retrained development baseline/candidate flags 2/107 versus 4/107 real bugs high, but 16/107 versus 12/107 medium+;
clean high alerts rise 78/9,177→97/9,177 and fixed-code high alerts 0/101→3/101. Candidate rejected; served weights unchanged.
The 1.87-point high-recall gain has grouped 95% interval 0–5.46 points. This compares two refits, not deployed weights or a fresh sealed test.

## Limits

- v1 was frozen before its sealed test; v2 design used v1 test results. Two of 27 held-out repositories have forks in training;
  public-code pretraining may also have seen test repositories. Four-fifths of training groups fit the v2 LLM;
  the held-out threshold fifth contained 78 real positives, only 2 detected high.
- Thresholds target 1% high/5% medium false alarms per function, not per contract. Whole-file high alerts are 2.2% v1 and 3.7% v2.
  Code-based blocking also requires a high-severity rule on the same function. Trivial functions receive rules but no model score.
- At a 1/100 buggy-function prevalence, estimated precision is about 7% high/3% medium+, versus 38%/20% in the sampled test mix.
  Including fixed-code alerts lowers sampled precision to 34%/18%.
- Added service Cargo context was compared in-sample. MPS calibration used bf16; CPU uses fp32. NEP-330 source is receiver-controlled
  and not matched to deployed WASM; a pinned source link still warns.

`uv run python -m unittest near.model.test_predict near.model.test_freeze_v2` checks model handling.
Frozen feature/model files are hash-pinned. Keep sealed reports and `.started` markers; a fresh accuracy claim needs fresh data.
