# NEAR Intents transaction anomaly detector: build spec

**Goal.** A transaction-level detector for NEAR Intents (`intents.near`, source github.com/near/intents). It flags
transactions whose receipt graph looks like an attack, and it feeds a signal into the oracle's `/v1/check`. This is
separate from the code-risk model under `near/model/` and from the EVM model.

**Why an anomaly detector, not an exploit classifier.** Real attack transactions on NEAR Intents are few, about 75
strong and 300 weak, from about 5 actors:
- the 2026-10-01 exploit: 23 failing Notify deposits plus 52 setup and cashout transactions;
- the April out-of-gas callback attempts;
- the May token-spoof and admin-method fuzzing.

A supervised classifier trained on them would learn those actors' fingerprints. So:
1. Learn what normal looks like from a large sample of real Intents transactions (tens of thousands or more).
2. Score transactions with interpretable invariant rules plus an anomaly model.
3. Hold every real attack campaign out, and report each one as a case study.

Optionally, a supervised head can be trained on sandbox-generated attack variants. It must never see the real positives.

## Layout (one owner per file set; do not edit another area's files)

| Path | What | Owner |
|---|---|---|
| `near/intents/fastnear.py`, `collect.py`, `test_collect.py` | FastNEAR client and bulk collection | collector |
| `near/intents/features.py`, `test_features.py` | receipt-graph features and rule hits | features |
| `near/intents/synthetic/` | sandbox replay of attacks on vulnerable contract versions | synthetic |
| `near/intents/model.py`, `evaluate.py`, `test_model.py`, `near/intents/reports/` | training, thresholds, freeze, case studies | model |
| `near/service/*` (intents signal), `near/README.md` section, `near/demo/` | oracle integration | integration |
| `near/data/intents/`, `near/models/intents_*` | data and frozen model; gitignored | — |

Python runs from the repo root (`.venv/bin/python -m near.intents.collect ...`). Do not edit `pyproject.toml` or
`uv.lock`; use what is installed (httpx, numpy, scipy, scikit-learn, fastapi). Do not run git commands that change
state. Follow TDD. Test output must be clean. Downloaded data is untrusted: parse it, never execute it.

## Data

**Source.** FastNEAR Transactions API, free, no key.
- `POST https://tx.main.fastnear.com/v0/account` with `{account_id, from_tx_block_height?, to_tx_block_height?,
  desc?, limit<=200, resume_token?, is_signer?, is_receiver?, is_action_arg?, is_event_log?, is_success?}`. It returns
  tx hashes plus `txs_count`.
- `POST https://tx.main.fastnear.com/v0/transactions` with `{tx_hashes: [<=20]}`. It returns full transactions: the
  transaction, the execution outcome, every receipt with its outcome (status, logs, gas) and data receipts.
- Rate limit is about 60 requests a minute per IP. Pace at 1 request a second and back off on 429. Parallel workers
  only produce 429s.
- The API repeats about 6 hashes per 1,000; dedupe by hash.

**Only the collector calls FastNEAR in bulk.** Others use the files it writes.

**Raw record.** One FastNEAR transaction JSON per line in gzip JSONL, exactly as returned, plus a top-level `"_meta":
{"source", "fetched_at", "label", "campaign", "role"}`.

| File | What |
|---|---|
| `near/data/intents/normals.jsonl.gz` | Sampled across intents.near history, stratified by month (block-height windows). Includes the transactions that start on other contracts (HOT Omni `mt_batch_transfer_call`, POA `ft_deposit`) by using the account index (`is_receiver` / `is_action_arg`), not only `receiver == intents.near`. Normal failures stay normal. |
| `near/data/intents/labelled.jsonl.gz` | The 570 labelled transactions from the scouting, with full receipts, labels from `all_labelled_txs.jsonl`. |
| `near/data/intents/synthetic/*.jsonl.gz` | Sandbox transactions, attack and benign, in the same shape where possible. |

Seeds from the scouting (a local working directory, not in the repo; the label file ships as
`near/data/intents/all_labelled_txs.jsonl` in `archives/near_intents.zip`):
- `intents-exploits/all_labelled_txs.jsonl`: 570 hashes with incident and role;
- `bulk-access/data/*`: 7,735 normal transactions already pulled, and the 23 exploit transactions;
- `bulk-access/scripts/fastnear_pull.py`, `graph.py`;
- `synthetic-attacks/`: intents repo clone; vulnerable v0.4.2 wasm built with `RUSTUP_TOOLCHAIN=1.86.0 cargo build
  ...`, see `BUILD_COMMANDS.txt`.

**Labels.** Positives are graded by role:
- `exploit` (23): strong;
- `attempt` (about 414): weak; some are plain malformed requests;
- `setup`, `cashout`, `setup_funding_via_intents`: attacker-cluster transactions with ordinary shape. Report them
  separately, never count them as misses of the anomaly detector.

Negatives: `team_regression_test` (17) and every normal. Labels for the exploit must come from receipt-level failure
(`*_resolve_deposit` Failure) or a mint without a matching burn or refund. They must never come from tx-level success,
which reports the exploit as successful.

## Features (`near.intents.features`)

```python
tx_features(tx: dict) -> dict[str, float]   # FEATURE_KEYS, environment-invariant
rule_hits(tx: dict) -> list[dict]           # {rule, severity: high|medium|low, message}
```

**Environment-invariant.** No raw account names, block heights, timestamps, tx hashes, or absolute gas that differs
between sandbox and mainnet. Use structure, relative amounts (log scale, ratios), counts, flags and method categories.

**Rule ideas, each an interpretable invariant:**
- a `*_resolve_deposit` / `*_resolve_withdraw` / `*_resolve_transfer` callback failed;
- a log over 90% of the 16,384-byte log limit, or a failure mentioning the log limit;
- credit kept: an `mt_mint` or deposit into intents with no matching burn, while the token refunded the sender;
- refund requested is larger than the deposit;
- a Notify / `mt_on_transfer` to a receiver contract inside a deposit;
- a batch with many token ids, or dust padding (many tokens with tiny amounts next to one large one);
- a private or callback method (`*_resolve_*`, `on_*`, `mt_on_transfer` called directly by a signer);
- an admin or role method (`upgrade`, `acl_*`, `add_relayer_key`, `ft_force_withdraw`, `pause`...) by a non-role
  caller;
- out-of-gas in a callback;
- a deserialize or panic failure on `execute_intents`. This is common in normal traffic too, so it gets a low weight.

## Model and evaluation (`near.intents.model`, `evaluate`)

**Anomaly model.**
- An anomaly model on the normals only, e.g. IsolationForest on `tx_features`, or a robust per-flow-type density.
- Combined risk = max(rule severity weight, anomaly percentile).
- Thresholds come from a time-later normal holdout:
  - `high` = at most 1 in 10,000 normal transactions;
  - `medium` = at most 1 in 1,000.
- Report the expected alerts per day at about 97k Intents transactions a day.

**Evaluation, honest and split by time and campaign.**
- Normals are split by time: the latest months form the test set.
- Every real campaign is held out from training (the anomaly model never sees positives).
- Report per campaign:
  - flagged at high, at medium, or missed;
  - which rules fired;
  - Wilson 95% intervals where counts allow.
- Report the false-alarm rate on test normals, per flow type, and per day.
- Count setup and cashout rows separately.

**Optional supervised head on synthetic variants.** Train only on synthetic attacks against synthetic plus real
normals. First run a domain check: a classifier separating benign-sandbox from mainnet normals on `tx_features`
should be near chance. If it isn't, fix the features or drop the head.

**Freeze.** Write `near/models/intents_v1.{pkl,json}` with sha256 of the feature code and the training ids, as in
`near/model/freeze.py`. Write a reports markdown under `near/intents/reports/`.

## Integration (`near.service`)

- `POST /v1/intents/score {tx_hash, sender_id?}`: fetch through FastNEAR, return risk, label, rule hits and features.
- In `/v1/check`, add an `intents_activity` signal:
  - score the receiver's most recent Intents transactions, about 20, through the FastNEAR account index;
  - `warn` if any is `high`, with the reasons;
  - never `block` on this alone;
  - an unreadable signal warns, as the policy requires.
- README section and a demo card. Tests do not mock end-to-end behaviour; unit tests may use recorded FastNEAR
  fixtures saved from real responses.
