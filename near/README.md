# Run it

[Overview](../README.md) · [Intents evidence](intents/reports/RESULTS.md) · [Agent](agent/README.md) · [Contracts](contract/README.md)

## 1. Install

Needs **Python 3.12+**, [uv](https://docs.astral.sh/uv/) and Git LFS. Run from the repo root:

```bash
git lfs pull --include "archives/near_models.zip,archives/near_intents.zip"
unzip -o archives/near_models.zip
unzip -o archives/near_intents.zip
uv sync
```

The default code model is v1. No wallet, API key or LLM download is needed.

## 2. Replay it offline

```bash
uv run python -m near.demo.replay
```

| Recorded input | Expected result |
|---|---|
| October exploit | **high** + failed callback / credit / log reasons |
| Normal deposit | **low** |
| Exploiter's recent history | **10 / 20 high** |

Uses recorded FastNEAR responses and the real frozen model. No network or payments; prints artifact hashes.

## 3. Check a transaction

```bash
uv run uvicorn near.service.app:app --port 8000
```

Open **<http://localhost:8000/demo/>** and paste any mainnet transaction hash. Needs internet; reads come from
FastNEAR's free tier, no key. Or from a second terminal:

```bash
curl -s localhost:8000/v1/intents/score -H 'content-type: application/json' \
  -d '{"tx_hash": "3k91uDpUiezxUe7hBgAR7kc3TBkToMZKGAiv6GqbtKiC"}'
```

You should see `"label": "high"` with `rule_hits` for `failed_resolve_callback`, `log_limit` and `credit_kept`
(high) plus three medium rules. The normal deposit `8tTzvGLMV7x1swmF2A5m3zDugCimdwmDrTXDTvKsJvj` gives `"label": "low"`
and no rule hits.

| Field | Meaning |
|---|---|
| `label` | `high` = Malicious pattern, `medium` = Suspicious, `low` = No known attack pattern (not "safe") |
| `rule_hits` | Each rule that fired, with its severity and a one-line reason |
| `top_features` | Receipt-graph features furthest from normal Intents traffic |
| `touches_intents` | `false` means the tx does not touch NEAR Intents; thresholds were calibrated there, so trust it less |
| `receipts_complete` | `false` means FastNEAR left out receipts; rules may have missed something |
| `risk` | Rule weight or anomaly percentile; not a probability of attack. Use `label` |

## 4. Scan an account or protocol

```bash
curl -s localhost:8000/v1/intents/scan -H 'content-type: application/json' \
  -d '{"account_id": "intents.near"}'
```

Of the account's 40 most recent transactions, returns up to 20 that touch NEAR Intents, newest first, each with `label`, `rules`
and `receipts_complete`, plus `counts` per label. On 2026-11-14 `intents.near` gave 20 low; this is live traffic,
so it changes. The exploiter account `20e6bfe4685d99004fc2095d3a0fc6158cd810ce8f801196141e183ed6e19d65` gives
10 high and 10 low. Results are cached for 5 minutes. A bad account id is a 422; FastNEAR errors are 502 or 504.

## 5. Agent payment guard (optional)

A separate component: an oracle contract, a guarded payment router and a scoped-key agent wrapper. Needs **Rust**
and **Node 22+**. The pinned Rust toolchain installs on first use.

```bash
cargo +1.95.0 install cargo-near --version 0.23.0 --locked
(cd near/contract && cargo test)
(cd near/agent && npm ci && npm test && npm run demo)
```

Expected: **18 contract tests**, **28 agent tests**, **12 attack checks** pass.
The merchant gets paid; the drainer gets nothing. [Read the log](agent/attack_demo.log).
`POST /v1/check` (below) is the receiver check it calls. Set `NEARBLOCKS_API_KEY` for its account-history
signals; without it NearBlocks rate-limits them and checks warn.

## API

| Endpoint | Input | Returns |
|---|---|---|
| `POST /v1/check` | `receiver_id`, optional `agent_id`, `deposit_yocto` | Decision, reasons, source signals |
| `POST /v1/intents/score` | `tx_hash` | Label, rule hits, model identity |
| `POST /v1/intents/scan` | `account_id` | Up to 20 Intents txs among the account's 40 most recent, scored, with counts per label |
| `POST /v1/analyze` | `source_files` mapping path → Rust code | Function risks and detector hits |
| `POST /v1/report` | `account_id`, `evidence_url` | Pending report; confirmation needs operator token |
| `GET /v1/health` | — | Active model and network |

Interactive API reference: **<http://localhost:8000/docs>**.

Signals behind `POST /v1/check`, the receiver check used by the payment guard:

| Signal | Data source |
|---|---|
| Account, contract hash | NEAR RPC `view_account` |
| Age, deployments, previous interactions | NearBlocks account APIs |
| Source code | NEP-330 metadata → GitHub commit; **self-declared, not WASM-verified** |
| Suspicious Intents activity | FastNEAR account index → transaction receipts |
| Reports / attested verdicts | Local evidence store + on-chain oracle views |

Because contract source is self-declared, a contract receiver currently gets at best **warn**; only plain accounts
can reach **allow**.

Configure `NEAR_NETWORK`, `NEAR_RPC_URL`, `ORACLE_CONTRACT_ID`, `NEARBLOCKS_API_KEY`,
`ORACLE_BLOCKLIST_PATH`, `ORACLE_ADMIN_TOKEN` as needed. Defaults target mainnet reads; do not expose the
unauthenticated demo publicly without request limits and report authentication.

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

</details>
