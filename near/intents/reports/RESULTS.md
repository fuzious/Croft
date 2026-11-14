# Intents detector: evidence

[Overview](../../../README.md) · [Raw evaluation](evaluation.json) · [Paused-traffic diagnostic](paused_diagnostic.json)

**Rules supplied every campaign detection. The anomaly model added none.**

## Results

| Campaign | High | Medium | Missed |
|---|---:|---:|---:|
| October exploit | **23** | 0 | 0 |
| April out-of-gas attempts | 0 | 53 | 2 |
| May admin fuzzing | 0 | 110 | 67 |
| May token spoofing | 0 | 18 | 164 |
| Team regression tests (negatives) | 0 | **12 false alarms** | 5 |

The 23 exploits repeat one technique by one actor. Rules were written after observing these campaigns;
these are retrospective case studies, **not unseen-attack accuracy**. Setup and cashout transactions have ordinary
shapes and are not detected.

| Clean test normals (7,400 transactions) | High alerts | Medium or higher |
|---|---:|---:|
| Rules only | 0 | 0 |
| Rules + anomaly model | **0** | **84 (1.14%)** |

Zero observed high alerts has a 95% Wilson upper bound of **0.052%**, not a zero population false-positive rate.
80 of the 84 medium alerts came from deposits during one paused-contract hour. The medium target of 0.1% was
missed. Excluding paused traffic gives 4/7,301 alerts, but that exclusion is post hoc.

**Policy:** high Intents activity warns; medium is informational. Neither blocks by itself.

## What was evaluated

| Slice | Period | Transactions |
|---|---|---:|
| Train | Nov 2024–May 2026 | 69,863 |
| Calibration | Jun–Sep 2026 | 17,772 |
| Test | Oct–Nov 2026 | 12,463 |

IsolationForest uses 63 receipt-graph features alongside 12 rules. No labelled campaign trained the anomaly model.
Use `label` for decisions: `risk` includes an anomaly percentile and is not a probability of attack.

## Limits that matter

- **Clean sample:** only 7,400 test rows are independent of rule development. The other 5,063 test rows and 2,672
  calibration rows were scouting seeds used while developing rules. Samples arrive in consecutive pages;
  correlated transactions make independent-sample confidence intervals optimistic.
- **Feature design saw the exploit.** Replacing 11 rule-like features with training medians removes the anomaly
  model's October detection. Its value against unseen attacks is unproven.
- **Sparse calibration:** no withdrawals, only 227 other-flow transactions, and one permitted high alert.
  A 1-in-10,000 high false-alarm rate is not established by this sample.
- **Historical false alarms:** rules flagged 327/69,863 training normals at medium. One training and one calibration
  normal triggered high rules; neither was investigated. Quiet test months do not guarantee quiet future traffic.
- **Training contamination:** four training normals were signed by an attacker-adjacent setup account. Future
  collection excludes these signers; the shipped model was not retrained.
- **Receiver coverage:** only 40 recent index rows / 20 Intents transactions, cached five minutes. History can be
  pushed out of the window; merely appearing in a suspicious receipt can cause a warning.

<details>
<summary>Evaluation history and reproduction</summary>

Model selection changed once after calibration revealed a candidate's score ceiling was unusable; see
[initial selection](freeze_first_pass.json). The test was scored twice following a nonfunctional code-hash change:
[first run](evaluation_sealed_run1.json) and [current run](evaluation.json) have the same measurements.
Paused-traffic analysis, source splits and feature ablation were performed after seeing test results.

A synthetic-data head was **not adopted**: it added zero detections and promoted 80 normal transactions to high.
Its adoption decision also read the test set. See [head results](head_evaluation.json),
[domain check](head_domain_check.json) and [sandbox setup](../synthetic/README.md).

The former 97,000-transactions/day planning estimate was unverified. Do not extrapolate the sample into an
operational daily-alert claim; bursty paused traffic dominates the pooled rate.

```bash
uv run python -m near.demo.replay
uv run python -m unittest near.intents.test_model near.service.test_intents
```

`archives/near_intents.zip` supplies the frozen model and labelled data. It excludes the 239 MB normals and scouting
seeds. Re-pulling normals does not reproduce the exact sample. `near.intents.model freeze` replaces model artifacts;
`near.intents.evaluate run --rescore` replaces evaluation results. Preserve the shipped evidence before either.

</details>
