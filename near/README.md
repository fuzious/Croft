# Run the Protocol Security Agent

[Overview](../README.md) · [Detection evidence](intents/reports/RESULTS.md) · [Optional response contracts](contract/README.md)

## Start

Needs **Python 3.12+**, [uv](https://docs.astral.sh/uv/) and Git LFS. Run from the repository root:

```bash
git lfs pull --include "archives/near_models.zip,archives/near_intents.zip"
unzip -o archives/near_models.zip
unzip -o archives/near_intents.zip
uv sync
uv run uvicorn near.service.app:app --port 8000
```

Open **<http://localhost:8000/demo/>**. No wallet or keys needed. Live transaction reads use FastNEAR mainnet;
network failures and rate limits are shown as errors, not clean results.

## Demo flow

1. **Inspect a transaction:** paste a NEAR mainnet hash or select an exploit/normal preset.
2. **Read the evidence:** assessment, attack categories, deposit accounting, receipt coverage and earlier activity.
3. **Scan a protocol:** enter `intents.near` or the exploiter account, then open a transaction from the results.
4. **Show the limitation:** the missed token-spoof preset demonstrates that a low score does not establish safety.

For a deterministic replay using recorded mainnet responses:

```bash
uv run python -m near.demo.replay
```

Expected: exploit high, normal low, and 10 high out of 20 transactions in the exploiter's recorded activity.
This runs the frozen scorer, prints artifact hashes and makes no network requests.

## API

```bash
curl -s localhost:8000/v1/transactions/score -H 'content-type: application/json' \
  -d '{"tx_hash":"3k91uDpUiezxUe7hBgAR7kc3TBkToMZKGAiv6GqbtKiC"}'

curl -s localhost:8000/v1/protocols/scan -H 'content-type: application/json' \
  -d '{"account_id":"intents.near"}'
```

| Endpoint | Purpose |
|---|---|
| `POST /v1/transactions/score` | Inspect one transaction; input `tx_hash`, optional `sender_id`, `include_history` |
| `POST /v1/protocols/scan` | Inspect recent Intents activity; input `account_id` |
| `POST /v1/analyze` | Supporting Rust source analysis; input `source_files` mapping |
| `GET /v1/health` | Model and service configuration |

The existing `/v1/intents/score` and `/v1/intents/scan` routes remain compatible aliases.
Scans also return `assessment_counts` and `n_incomplete`, so unknown evidence is not counted as clean.
Interactive schemas: **<http://localhost:8000/docs>**.

| Response field | Read it as |
|---|---|
| `assessment`, `assessment_reason` | Interpretation and why: malicious_pattern / suspicious / no_known_pattern / inconclusive / unsupported |
| `label` | Raw detector severity: high / medium / low; not proof of malicious intent or safety |
| `rule_hits` | Observed rules, severity and reasons |
| `touches_intents` | Whether the transaction is within the detector's intended protocol scope |
| `evidence_coverage`, `receipts_complete` | Observed/missing receipts and pending outcomes; whether the graph is complete |
| `accounting` | Exact token-unit deposit/refund/credit checks; successful events, not independently verified balances |
| `history` | Strictly earlier related activity; unavailable or bounded coverage stays explicit |
| `attack_categories` | Categories of observed patterns, not verified root causes |
| `baseline`, `detector` | Original model result and separate identities for the added evidence checks |
| `risk` | Rule weight or anomaly percentile; **not an attack probability** |

Any well-formed mainnet hash can be submitted. Detection is calibrated on **NEAR Intents**; unsupported or incomplete
results are identified explicitly. A scan considers 40 recent account-index rows, scores up to 20 Intents transactions,
and caches successful results for five minutes. It is not continuous monitoring or a complete protocol audit.

`include_history` defaults to `false` in the API; the demo enables it. It adds at most four reads for two participant
accounts, up to 20 earlier index rows each. Each read has a six-second network deadline. If history fails, the
transaction result remains visible with history marked unavailable. Scans reuse their existing transaction window.
History links require matching authenticated participants and earlier completed receipts; shared relayers are excluded.

## Optional response layer

Transaction analysis is read-only. Operators may separately use `POST /v1/report` to file evidence and `/v1/check`
to obtain an **account policy verdict**. The [on-chain contracts](contract/README.md) and
[response client](agent/README.md) govern future payments through the supplied router; they are not required for
this demo. A high transaction label does not automatically publish a block or prove its signer is an attacker.

Those integrations use `NEAR_NETWORK`, `NEAR_RPC_URL`, `ORACLE_CONTRACT_ID`, `NEARBLOCKS_API_KEY`,
`ORACLE_BLOCKLIST_PATH` and `ORACLE_ADMIN_TOKEN`. The score/scan data source remains mainnet FastNEAR.
Keep the demo local unless you add request quotas and report authentication.

<details>
<summary><b>Tests, optional LLM and research data</b></summary>

```bash
uv run python -m unittest discover -s near -t . -p 'test_*.py'
```

Expected: `OK`. Tests that need an optional archive or the opt-in sandbox skip when it is missing.

The v2 code LLM weights (`archives/near_llm_v2.zip`, about 0.9 GB) are not in the repository, so the service runs
v1. With the weights unpacked at the repo root:

```bash
uv sync --extra llm
uv run --extra llm uvicorn near.service.app:app
```

Without weights or LLM dependencies, automatic selection uses v1.
`NEAR_ORACLE_MODEL=frozen_near_v1` explicitly selects v1.

Training data: fetch and unpack `archives/near_datasets.zip`. Reproduction details:
[Intents evaluation](intents/reports/RESULTS.md) · [code-model evaluation](model/reports/RESULTS.md).
Do not refreeze over the shipped artifacts unless you intend to replace them.

The transaction research archive contains the trained candidate, hash-pinned feature matrix, generated data,
fresh unlabelled sample and per-row evaluation records. **The candidate failed promotion checks and is not served.**

```bash
git lfs pull --include "archives/near_transaction_research.zip"
unzip -o archives/near_transaction_research.zip

# Refit from the recorded feature matrix into a new directory
uv run python -m near.intents.train_transactions run \
  --feature-cache near/models/transactions_v2_features.pkl --output-dir /tmp/near-transaction-experiment

# Inspect the research candidate separately from the API
uv run python -m near.intents.train_transactions score \
  --transaction near/intents/fixtures/features/exploit_3k91uD.json.gz
```

Matrix reproduction avoids downloading the original normals; raw feature extraction still needs them.
The [sandbox setup](intents/synthetic/README.md) supplies the binary/WASMs for generating new controlled cases:

```bash
uv run python -m near.intents.synthetic.families_v2 --out /tmp/near-family-data --report /tmp/near-family-data.json
uv run python -m near.intents.synthetic.families_v2 --out /tmp/near-family-data --report /tmp/near-family-data.json --supplement
```

Earlier parameter-only experiments also retained the served models. To reproduce those separately:

```bash
uv run python -m near.model.train_candidate --output-dir /tmp/near-code-experiment
uv run python -m near.intents.train_candidate --output-dir /tmp/near-intents-experiment
```

Code training needs `train_v2.jsonl` and its source repositories or matching feature cache (`--cache-dir`).
Intents training needs the original normals and feature cache; these are local research data, not included in the
demo archive. The commands refuse to overwrite an existing experiment report.

</details>
