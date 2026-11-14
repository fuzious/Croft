# Run the Security Oracle

[Overview](../README.md) · [Detection evidence](intents/reports/RESULTS.md) · [Optional response contracts](contract/README.md)

## Start

Needs **Python 3.12+** and [uv](https://docs.astral.sh/uv/). The transaction demo does not need Git LFS:

```bash
git clone -b near-security-oracle https://github.com/fuzious/security_oracle.git
cd security_oracle
unzip -o archives/near_intents.zip
uv sync
uv run uvicorn near.service.app:app --port 8000
```

Open **<http://localhost:8000/demo/>**. No wallet or keys needed. Live transaction reads use FastNEAR mainnet;
network failures and rate limits are shown as errors, not clean results.

## Investigation workflow

1. **Inspect a transaction:** paste a NEAR mainnet hash or select an exploit/normal preset.
2. **Read the evidence:** assessment, attack categories, deposit accounting, receipt coverage and earlier activity.
3. **Scan a protocol:** enter `intents.near` or the exploiter account, then open a transaction from the results.
4. **Interpret coverage:** “Not flagged: rejected overdraw probe” is a failed probe, not evidence of a successful exploit.

The April preset has callback out-of-gas evidence. Across that campaign, **41 of 53 detections** only mean
“deposit used Notify”; they do not establish that an out-of-gas attack occurred. Wallet drainers are not covered.
Its earlier-activity panel can show “unavailable” when FastNEAR's answer exceeds the 8 MB cap.

For a deterministic replay using recorded mainnet responses:

```bash
uv run python -m near.demo.replay
```

Expected final check: `PASS: exploit high; normal low; account history 10/20 high.`
This runs the frozen scorer, prints artifact hashes and makes no network requests.

## Human review

Open **<http://localhost:8000/human/>** to review suspicious and high-severity findings from transaction
inspections and account scans. Search and filter the queue, inspect the original evidence, and save a
confirmation or dismissal with a review note. Cases persist locally across service restarts.

The demo requires no authentication and supports explicitly loading labelled historical cases.
Review decisions do not change on-chain policy. [Dashboard details](human/README.md).

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
| `POST /v1/preapprovals` | Operator-authenticated signature for one exact router payment |

`/v1/intents/score` and `/v1/intents/scan` are aliases of the score and scan routes.
`/v1/health`'s `model` field describes the optional source-code model; the transaction model identity is in each
score/scan response.
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
transaction result remains visible with history marked unavailable. Scans reuse the transaction window they scored.
History links require matching authenticated participants and earlier completed receipts; shared relayers are excluded.

## Optional response layer

Transaction analysis is read-only. Operators may separately use `POST /v1/report` to file evidence and `/v1/check`
to obtain an **account policy verdict**. The [on-chain contracts](contract/README.md) and
[response client](agent/README.md) govern future payments through the supplied router; they are not required for
this demo. A high transaction label does not automatically publish a block or prove its signer is an attacker.

Those integrations use `NEAR_NETWORK`, `NEAR_RPC_URL`, `ORACLE_CONTRACT_ID`, `NEARBLOCKS_API_KEY`,
`ORACLE_BLOCKLIST_PATH` and `ORACLE_ADMIN_TOKEN`. The score/scan data source is mainnet FastNEAR.
Keep the demo local unless you add request quotas and report authentication.

## Signed payment pre-approvals

Calling `POST /v1/preapprovals` with `ORACLE_ADMIN_TOKEN` is the explicit operator approval.
It does not infer safety from a transaction score. Keep this token and the signing seed on your backend.
The API refuses locally blocked receivers; the oracle independently enforces on-chain blocks at verification.

1. Deploy fresh [oracle and router contracts](contract/README.md); their storage layout has changed.
2. Set `ORACLE_ADMIN_TOKEN`, `ORACLE_CONTRACT_ID`, and `ORACLE_PREAPPROVAL_SEED_BASE64`
   (base64 of a randomly generated 32-byte Ed25519 seed). Use a separate key per network.
3. As the oracle owner, call `set_preapproval_key({"public_key":"<base64 raw public key>"})`
   with exactly 1 yoctoNEAR. Set `ORACLE_PREAPPROVAL_KEY_GENERATION` to the generation returned by
   `get_preapproval_key({})` (the first registration is `"1"`). Restart the service with these settings.
4. Read `router.get_preapproval_nonce({"agent_id":"agent.human.testnet"})`, then request approval:

```bash
curl --fail-with-body localhost:8000/v1/preapprovals \
  -H "Authorization: Bearer $ORACLE_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"consumer_id":"router.testnet","agent_id":"agent.human.testnet",
       "receiver_id":"shop.testnet","amount":"1000000000000000000000000",
       "nonce":"0","ttl_seconds":300}'
```

Use the actual next nonce, not always `"0"`. The response contains `public_key`, `oracle_id`,
`verify_args` and `pay_args`. The signing seed is never returned. For example with a NEAR account client:

```js
const approved = await account.viewFunction({
  contractId: approval.oracle_id, methodName: 'verify_preapproval', args: approval.verify_args,
}); // true for a valid, unexpired approval
const result = await agent.functionCall({
  contractId: routerId, methodName: 'pay', args: approval.pay_args,
  gas: 100_000_000_000_000n, attachedDeposit: 0n,
});
```

Alternatively pass `approval.pay_args.preapproval` as `preapproval` to `payWithOracle` with
`createRouterPaySigner`. The existing scoped agent key still only needs the `pay` method.
The oracle view is read-only; single-use enforcement happens in the router. A refused payment consumes
its nonce but restores funds. Fetch a fresh nonce before retrying. The TTL is capped at 900 seconds;
rotating or disabling the public key invalidates outstanding signatures.

To derive the public key from your configured seed locally:

```bash
uv run python -c 'import os, base64; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; print(base64.b64encode(Ed25519PrivateKey.from_private_bytes(base64.b64decode(os.environ["ORACLE_PREAPPROVAL_SEED_BASE64"])).public_key().public_bytes_raw()).decode())'
```

Run the complete local API-to-contract proof with `cd near/contract && cargo test --test preapprovals`.

<details>
<summary><b>Tests, optional LLM and research data</b></summary>

```bash
uv run python -m unittest discover -s near -t . -p 'test_*.py'
```

Expected: `OK`. Tests that need an optional archive or the opt-in sandbox skip when it is missing.

Optional Rust source models use Git LFS:

```bash
git lfs pull --include "archives/near_models.zip"
unzip -o archives/near_models.zip
```

Without these weights, source analysis uses detectors only; transaction analysis still runs. Optional LLM weights
(`archives/near_llm_v2.zip`, about 0.9 GB) are not in the repository. They require `uv sync --extra llm`.

**Release freeze:** this release adds no training, features, thresholds or sandbox families. `intents_v1` and its
rules are what is served. The transaction research candidate is rejected.
[Results and audit](intents/reports/RESULTS.md).

Optional research artifacts:

```bash
git lfs pull --include "archives/near_transaction_research.zip"
unzip -o archives/near_transaction_research.zip
```

The archive contains the rejected candidate, fixed feature matrix, generated data and per-row records.
The sandbox evaluation is a **variant holdout of four scripted recipes**, not unseen-family accuracy.

Validate accounting without fitting a model (requires the original local datasets named in the report):

```bash
uv run python -m near.intents.validate_accounting --out /tmp/accounting-validation.json
```

[Checked-in accounting report](intents/reports/accounting_validation.json) includes input/source hashes and
coverage counts. The complete original normals and sandbox datasets are not bundled with the demo, so a plain
clone can run the replay and tests but cannot reproduce this full research measurement without those inputs.

</details>
