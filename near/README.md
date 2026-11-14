# Run the hackathon demo

[Overview](../README.md) · [Agent](agent/README.md) · [Contracts](contract/README.md)

## 1. Install

Needs **Python 3.12+**, [uv](https://docs.astral.sh/uv/) and Git LFS. Run from the repo root:

```bash
git lfs pull --include "archives/near_models.zip,archives/near_intents.zip"
unzip -o archives/near_models.zip
unzip -o archives/near_intents.zip
uv sync
```

The default code model is v1. No wallet, API key or LLM download is needed for the offline demo.

## 2. See the detector

```bash
uv run python -m near.demo.replay
```

| Recorded input | Expected result |
|---|---|
| October exploit | **high** + failed callback / credit / log reasons |
| Normal deposit | **low** |
| Exploiter's recent history | **10 / 20 high**; receiver policy warns |

Uses recorded FastNEAR responses and the real frozen model. No network or payments; prints artifact hashes.

## 3. Open the live UI

```bash
uv run uvicorn near.service.app:app --port 8000
```

Open **<http://localhost:8000/demo/>**. Live checks need internet. Set `NEARBLOCKS_API_KEY` for the account-history
signals; without it NearBlocks rate-limits them and checks warn.

## 4. Prove the payment guard

Needs **Rust** and **Node 22+**. The pinned Rust toolchain installs on first use.

```bash
cargo +1.95.0 install cargo-near --version 0.23.0 --locked
(cd near/contract && cargo test)
(cd near/agent && npm ci && npm test && npm run demo)
```

Expected: **18 contract tests**, **28 agent tests**, **12 attack checks** pass.
The merchant gets paid; the drainer gets nothing. [Read the log](agent/attack_demo.log).

## API

| Endpoint | Input | Returns |
|---|---|---|
| `POST /v1/check` | `receiver_id`, optional `agent_id`, `deposit_yocto` | Decision, reasons, source signals |
| `POST /v1/intents/score` | `tx_hash` | Label, rule hits, model identity |
| `POST /v1/analyze` | `source_files` mapping path → Rust code | Function risks and detector hits |
| `POST /v1/report` | `account_id`, `evidence_url` | Pending report; confirmation needs operator token |
| `GET /v1/health` | — | Active model and network |

Interactive API reference: **<http://localhost:8000/docs>**.

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
