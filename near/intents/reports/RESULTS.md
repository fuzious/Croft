# Intents detector: evidence

[Overview](../../../README.md) · [Accounting validation](accounting_validation.json) · [Release audit](release_evidence_audit.json)

**The accounting check agrees with recorded sandbox state and known exploit labels. This is not unseen-attack accuracy.**
This release serves the `intents_v1` model and rules as shipped; it adds no fits, features, thresholds or sandbox
families.

## Accounting first

| Evidence set | High accounting findings |
|---|---:|
| Sandbox: measured credit defects | **712 / 712** |
| Sandbox: other unpatched executions | **0 / 2,953** |
| Sandbox: patched verifier | **0 / 349** |
| Known real exploits | **23 / 23** |
| Sampled historical normals | **0 / 100,098** |

Across **4,014 sandbox executions**, there are 712 positive state measurements, 2,113 zero measurements and
**1,189 without direct state measurements**. No measured state label disagrees with the check. The 0/3,302 other
executions include unsuccessful probes and unmeasured flows; they are not all independently proved state-negative.
State zero means `ghost_credit == 0`; 329 attempt runs (318 in synthetic/attacks.jsonl.gz, 3 in the patched backport, 4 in v2 train, 4 in v2 test)
show measured unbacked burn (the token side lost backing without extra credit), which the check does not flag high.

Of the historical normals, **25,336 were checked, 4,984 inconclusive and 69,778 unsupported**. No finding is not
proof of safety. These are correlated samples from the research collection, not fresh tests. The real exploits
repeat one technique by one actor. Production accounting reconciles successful events; it does not independently
read opening/closing balances or establish token authenticity or protocol solvency.

Re-run without training, using the original local data listed and hashed in the report:

```bash
uv run python -m near.intents.validate_accounting --out /tmp/accounting-validation.json
```

The complete research datasets are not bundled with the demo. [Validator](../validate_accounting.py) ·
[Input hashes, state measurements and coverage](accounting_validation.json)

## What the served detector recognizes

**11-category taxonomy; served rules cover 3:** callback accounting, access-control abuse and resource exhaustion.
Wallet drainers are **not covered**. Accounting and bounded earlier-participant history add evidence, but no
additional campaign detections or alerts on the 7,400 historical clean test transactions.

| Receipt mechanism in the 437 campaign-labelled transactions | Rules + accounting, medium or higher |
|---|---:|
| Receipt-visible callback / Notify / private / admin patterns | **204 / 204** |
| Signed-intent probes | **0 / 194** |
| Other campaign calls: deposit, withdrawal, transfer or key calls | **0 / 39** |

Groups are defined from the same receipt signals the rules read, so 204/204 describes coverage of those patterns,
not detection accuracy. [Mechanism script](../audit/mechanism_table.py).

The 233 misses are **signed-intent and other campaign calls**, not all signed-intent fuzzing. These groups were
defined retrospectively. On the same 7,400 normal transactions, rules + accounting raised **0 medium-or-higher
alerts**. Adding the served anomaly model raised **84 medium alerts and 0 high alerts**, without more campaign detections.

| Retrospective campaign | High | Medium | Not flagged |
|---|---:|---:|---:|
| October exploit | 23 | 0 | 0 |
| April out-of-gas attempts | 0 | 53 | 2 |
| May admin fuzzing | 0 | 110 | 67 |
| May token-spoofing-labelled campaign | 0 | 18 | 164 |
| Team regression controls | 0 | 12 false alarms | 5 |

**41 of the 53 April detections only mean “deposit used Notify”.** They do not establish an out-of-gas attack.
The April demo preset is `Ete7rqrC1EFpj2ZFK4BY2vqDHtTUXmiHqfwsg1mR3k5i`, which also has callback out-of-gas evidence.
The 18 May token-campaign detections are direct private-method probes, not token-authenticity checks.
The May token-campaign preset is **“Not flagged: rejected overdraw probe”**; its failure says insufficient balance
or overflow, not that a successful spoof occurred.

All campaign rows use the frozen served detector: **0 high / 84 medium-or-higher alerts on 7,400 normals**.
Rules were written after seeing these campaigns. The anomaly model supplied no extra detections; 80 of its 84
medium alerts came from one paused-contract hour. Zero observed high alerts has a 95% Wilson upper bound of
0.052%, with transaction correlation making this interval optimistic.

## Research candidate: rejected

The **204→353/430** family-holdout result pools four refits. The two May families share a funder:
it measures **same-attacker-cluster transfer**, not demonstrated unseen-attacker generalization. Each row below
pairs recall with alerts from that exact refit and its thresholds; do not pair the total with the full-fit model's 14 alerts.

| Family held out | Rules → candidate, medium+ | High alerts / 7,400 normals | Medium+ alerts / 7,400 |
|---|---:|---:|---:|
| Access control | 110 → 145 / 174 | **88** | 88 |
| Callback accounting | 23 → 23 / 23 | **0** | 0 |
| Resource exhaustion | 53 → 53 / 55 | **6** | 6 |
| Token spoofing | 18 → 132 / 178 | **594** | 594 |

Holding out the funding-linked attacker cluster reduces the pooled improvement to **204→216/430**:

| Actor held out | Rules → candidate, medium+ | High alerts / 7,400 normals | Medium+ alerts / 7,400 |
|---|---:|---:|---:|
| May cluster, both families | 128 → 140 / 352 | **122** | **125** |
| October exploiter | 23 → 23 / 23 | 0 | 0 |
| April actor | 53 → 53 / 55 | 6 | 6 |

These normal counts cannot be pooled into one deployed-model rate. [holdout_check.py](../audit/holdout_check.py)
refits each fold deterministically from the research feature matrix and reproduces these alert counts and rounded
thresholds exactly; the fold weights are not saved. Family positive counts also match the saved per-row
predictions. [Audit and provenance](release_evidence_audit.json).

The separate full-fit candidate raised **14 high alerts / 7,400 normals** and **26 high alerts / 40 generated benign
controls**. A source classifier perfectly separated sampled generated and real benign traffic. The candidate
remains rejected and is never selected by the API. [Original experiment](transactions_v2.json).

## Data boundaries

| Added evidence | What it supports |
|---|---|
| 273 sandbox transactions: 6 measured exploits, 132 attempts, 135 benign | A **variant holdout of four scripted recipes**, sharing generator and verifier builds |
| 3 sourced Rhea / Skyward exploits | Two protocol families outside current Intents coverage |
| 500 fresh transactions, unknown labels | Zero observed alerts in a correlated 112-second window; no accuracy or false-positive-rate claim |

Seven of the original 437 attack-labelled rows do not reach Intents. Their labels remain intact, outside the
research classifier's 430-row scope. Four attacker-adjacent normal rows were excluded from research fitting;
the shipped model was not retrained. [Sandbox provenance](synthetic_families_v2.json) ·
[External case sources](../fixtures/cases_v2/manifest.json).

<details>
<summary>Historical evaluation and limitations</summary>

- Baseline normal windows: train 69,863 (Nov 2024–May 2026), calibration 17,772 (Jun–Sep 2026), test 12,463
  (Oct–Nov 2026). Only 7,400 test rows were independent of rule development; 5,063 test and 2,672 calibration
  rows were scouting seeds. [Original evaluation](evaluation.json).
- IsolationForest uses 63 receipt features beside 12 rules. Feature design saw the exploit. `risk` is not an attack
  probability; unseen-attack value remains unproven. Calibration had no withdrawals and only 227 other-flow rows.
- Historical rules raised medium alerts on 327 training normals and high alerts on one training and one calibration
  normal; those two highs were not investigated. Quiet test months do not establish a future population rate.
- The earlier parameter-only candidate raised 92 medium+ alerts / 7,400 versus the served model's 84, with 0 high
  alerts and no extra campaign detections. It was also rejected. [Report](training_candidate.json).
- A synthetic head was rejected after adding no detections and promoting 80 normals to high. Its adoption decision
  read the test set. [Head evaluation](head_evaluation.json) · [Domain check](head_domain_check.json).
- Model selection changed after calibration exposed an unusable score ceiling. The sealed test was scored twice
  after a nonfunctional code-hash change, with identical measurements. [Initial selection](freeze_first_pass.json) ·
  [First evaluation](evaluation_sealed_run1.json). Paused-traffic analysis and feature ablation were post hoc.
- Account scans inspect at most 20 Intents transactions from 40 recent index rows, cached five minutes. History is
  bounded; missing evidence remains explicit. Findings do not undo transactions, pause protocols or automatically
  publish account blocks.

The demo archive supplies the frozen model and labelled records; it omits the full normal/scouting datasets.
The validator refuses to overwrite a report file. Preserve the shipped evidence when running research tools.

</details>
