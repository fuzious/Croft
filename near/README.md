# Croft · NEAR

Investigate completed NEAR Intents transactions and review receipt, accounting and bounded history evidence.
Findings do not prove safety, stop transactions or automatically block an account. Wallet drainers are outside coverage.
[Transaction evidence](intents/reports/RESULTS.md) · [Source-model evidence](model/reports/RESULTS.md)

## Run

From the repository root, with Python 3.12+ and `uv`:

```bash
unzip -o archives/near_intents.zip
uv sync --locked
uv run uvicorn near.service.app:app --port 8000
```

Open <http://localhost:8000/demo/>, <http://localhost:8000/human/> or the [API schemas](http://localhost:8000/docs).
The transaction demo needs no wallet, keys or Git LFS; live reads use FastNEAR mainnet.
Keep it local: the review dashboard has no authentication, and public deployment needs quotas and report authentication.

```bash
curl -s localhost:8000/v1/transactions/score -H 'content-type: application/json' \
  -d '{"tx_hash":"3k91uDpUiezxUe7hBgAR7kc3TBkToMZKGAiv6GqbtKiC"}'
curl -s localhost:8000/v1/protocols/scan -H 'content-type: application/json' \
  -d '{"account_id":"intents.near"}'
uv run python -m near.demo.replay
```

The offline replay should end `PASS: exploit high; normal low; account history 10/20 high.`
Any well-formed mainnet hash is accepted, but detection is calibrated on Intents. Missing evidence stays inconclusive.
Scans score up to 20 Intents transactions from 40 recent rows and cache results for five minutes; this is not monitoring.
`include_history` defaults to false in the API; the demo enables bounded earlier-participant reads. Shared relayers are excluded.
`risk` is a rule weight or anomaly percentile, not an attack probability. Accounting reconciles events, not independent balances.

Suspicious/high findings enter the human queue. Confirm/dismiss with a note; reopening and labelled historical demo cases are supported.
Decisions persist in `data/human_reviews.sqlite3` (`ORACLE_REVIEW_DB` overrides it); repeated scoring preserves the original snapshot.
Reviews are local annotations, not blocklist updates or on-chain actions. The queue refreshes every 15 seconds.
API: `GET /v1/reviews`, `PATCH /v1/reviews/{id}` with `{status,note}`, `POST /v1/reviews/demo`.

## Tests and optional response contracts

```bash
uv run python -m unittest discover -s near -t . -p 'test_*.py'
(cd near/agent && npm ci && npm test)  # Node >=22
cargo +1.95.0 install cargo-near --version 0.23.0 --locked  # once
(cd near/contract && cargo test)
(cd near/agent && npm run demo)
```

Optional-data/sandbox Python tests skip without their inputs. Rust tests build WASM and use a local NEAR sandbox;
run `uv sync` first because pre-approval tests invoke the root `.venv`. The adapter demo uses nearcore 2.14.1;
the older npm sandbox cannot load these contracts. The invoice parser is scripted, not an LLM.

[security_oracle](contract/security_oracle/src/lib.rs) records trusted account verdicts and confirmed reports;
[guarded_router](contract/guarded_router/src/lib.rs) restricts future payments from its owner-funded agent balances.
These sandbox-tested contracts are unaudited and need fresh deployments: this revision has no migration for older storage.
Build outputs: `near/contract/target/near/{security_oracle,guarded_router}/*.wasm`.

The service integrations use `NEAR_NETWORK`, `NEAR_RPC_URL`, `ORACLE_CONTRACT_ID`, `NEARBLOCKS_API_KEY`,
`ORACLE_BLOCKLIST_PATH` and `ORACLE_ADMIN_TOKEN`. The [attester relay](agent/src/attester_relay.js) separately requires
`ORACLE_SERVICE_URL`, `NEAR_NODE_URL`, `NEAR_NETWORK_ID`, `ORACLE_CONTRACT_ID`, `ATTESTER_ID`, `ATTESTER_KEY`.
`node near/agent/src/attester_relay.js receiver.near 3600` writes a `/v1/check` account attestation on chain.
Transaction scores never invoke that command or confirm reports automatically. TTL is 1 second–7 days.

The [payment wrapper](agent/src/wrapper.js) refuses blocks and asks for human confirmation on warnings.
The router refuses warnings, expired/missing verdicts unless an explicit signed pre-approval is supplied; blocks and limits still apply.
Use decimal amount strings. Malformed/mismatched service answers block; service failures warn.
Scoped keys allow only this router's `pay`, one function-call action and zero attached deposit; use 100 Tgas.
Keep a recovery mechanism/full-access key: function-call-only accounts cannot recover exhausted or leaked keys.
The human owner retains withdrawal control. `set_limit`, `withdraw` and oracle owner changes require 1 yoctoNEAR.
Router reservations are restored on failed payments; daily caps reset at UTC block-timestamp midnight.
Attesters are trusted; removal permanently revokes their old verdicts. Confirmed blocks need an owner unblock.
The router cannot compare the receiver's current code hash: use short expiries and re-attest after redeployment.

## Signed payment pre-approvals

`POST /v1/preapprovals` is an explicit operator approval, not an inference from a transaction score.
Keep the admin token and signing seed on the backend; use a separate key per network.

1. Set `ORACLE_ADMIN_TOKEN`, `ORACLE_CONTRACT_ID`, `ORACLE_PREAPPROVAL_SEED_BASE64` (a random 32-byte Ed25519 seed, base64).
2. As oracle owner, call `set_preapproval_key({"public_key":"<base64 raw public key>"})` with exactly 1 yoctoNEAR.
3. Read `get_preapproval_key({})`, set `ORACLE_PREAPPROVAL_KEY_GENERATION` to its generation (initially `"1"`), and restart the service.
4. Read `router.get_preapproval_nonce({"agent_id":"agent.human.testnet"})` and use that value below, not always `"0"`.

```bash
curl --fail-with-body localhost:8000/v1/preapprovals \
  -H "Authorization: Bearer $ORACLE_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"consumer_id":"router.testnet","agent_id":"agent.human.testnet", "receiver_id":"shop.testnet",
       "amount":"1000000000000000000000000","nonce":"0","ttl_seconds":300}'
```

The response contains `public_key`, `oracle_id`, `verify_args` and `pay_args`, never the seed.
Call the oracle's `verify_preapproval` view with `verify_args`, then the router's `pay` with `pay_args`, 100 Tgas and zero deposit.
Alternatively pass `pay_args.preapproval` to `payWithOracle` with `createRouterPaySigner`.
The proof binds oracle, router, agent, receiver, amount, nonce, key generation and expiry; signatures/keys are raw Ed25519 bytes in base64.
TTL defaults to 300 seconds and is capped at 900. Every key update invalidates old signatures, including disabling/reinstalling a key.
The router consumes the nonce before its async call, including refused payments; fetch a fresh nonce/signature for every retry.
Local and on-chain blocks still refuse payment. Full message encoding is in [preapprovals.py](service/preapprovals.py).

## Optional models and research

```bash
git lfs pull --include 'archives/near_models.zip,archives/near_transaction_research.zip'
unzip -o archives/near_models.zip
unzip -o archives/near_transaction_research.zip
```

Without source weights, source analysis uses rules; transaction analysis still runs. Optional LLM weights
(`archives/near_llm_v2.zip`, about 0.9 GB) are not tracked and need `uv sync --extra llm`.
Research candidates are rejected; the API serves the frozen `intents_v1` model. Preserve report JSON and `.started` markers.
`uv run python -m near.intents.validate_accounting --out /tmp/accounting-validation.json` needs the original datasets
listed in [accounting_validation.json](intents/reports/accounting_validation.json); full research inputs are not bundled.

### Reproduce the synthetic sandbox

This optional harness does not train the served model. It requires near-sandbox **2.10.2** (`NEAR_SANDBOX_BIN_PATH`),
Rust **1.86.0**, Binaryen **116**, and a local `near/intents` clone. Set `REPO` to this repository, `INTENTS` to that clone,
`INTENTS_SYN_WASM_DIR` to an existing output directory and `WASM` to the same path. Set `INTENTS_V042_DIR` to the v0.4.2 worktree
for its `releases/fungible-token.wasm` and `releases/wnear.wasm` (default: `near/data/intents/synthetic/intents-v042`).

```bash
rustup toolchain install 1.86.0 --profile minimal -t wasm32-unknown-unknown
git -C "$INTENTS" worktree add ../intents-v042 6dad94cf8a9cf3083d9c1cf6c052ef8cdde0d473
cd "$INTENTS/../intents-v042"
RUSTUP_TOOLCHAIN=1.86.0 cargo build -p defuse --target wasm32-unknown-unknown --release --locked --no-default-features --features=contract,imt
RUSTUP_TOOLCHAIN=1.86.0 cargo build -p multi-token-receiver-stub --target wasm32-unknown-unknown --release --locked --no-default-features
rsync -a --exclude target --exclude .git ./ ../intents-v042-batchlimit/
(cd ../intents-v042-batchlimit && patch -p1 < "$REPO/near/intents/synthetic/patches/v0.4.2-batch-limit.patch" && \
 cd defuse && RUSTUP_TOOLCHAIN=1.86.0 cargo build --target wasm32-unknown-unknown --release --locked --no-default-features --features=contract,imt)
(cd "$REPO/near/intents/synthetic/mt_token" && CARGO_TARGET_DIR=/tmp/mt_target RUSTUP_TOOLCHAIN=1.86.0 \
 cargo build --offline --target wasm32-unknown-unknown --release)
wasm-opt -Oz --strip-debug target/wasm32-unknown-unknown/release/defuse.wasm -o "$WASM/defuse-v0.4.2.wasm"
wasm-opt -Oz ../intents-v042-batchlimit/target/wasm32-unknown-unknown/release/defuse.wasm -o "$WASM/defuse-v0.4.2-batchlimit.wasm"
wasm-opt -Oz target/wasm32-unknown-unknown/release/multi_token_receiver_stub.wasm -o "$WASM/multi_token_receiver_stub.wasm"
wasm-opt -Oz /tmp/mt_target/wasm32-unknown-unknown/release/synthetic_mt_token.wasm -o "$WASM/synthetic_mt_token.wasm"
cd "$REPO"
INTENTS_SANDBOX_E2E=1 uv run python -m unittest near.intents.synthetic.test_sandbox_e2e
uv run python -m near.intents.synthetic.generate --version v0.4.2 --attacks 700 --benign 700 --seed 7
uv run python -m near.intents.synthetic.families_v2
uv run python -m near.intents.synthetic.families_v2 --supplement
```

Outputs go to `near/data/intents/synthetic/`; use fresh `--out`/`--report` paths to protect existing research.
The baseline retains credit after a failed callback; the batch-limit backport rejects oversized deposits.
`exploit` requires measured positive unbacked credit; unsuccessful attempts remain `attempt`.
These are variant holdouts of four recipes, not unseen-family accuracy. Custom tokens, 300 TGas (mainnet used 1 PGas),
synthetic receipt IDs and incomplete benign flows limit realism; the patch does not test the later notification-removal fix.
