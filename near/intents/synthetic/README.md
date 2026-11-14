# Synthetic NEAR Intents transactions (sandbox replay)

This directory replays attacks on the real vulnerable NEAR Intents verifier (defuse v0.4.2, commit `6dad94cf`, the
version deployed during the 2026-10-01 exploit) in a local NEAR sandbox. It also runs ordinary benign traffic. Every
executed transaction is converted to the FastNEAR `/v0/transactions` record shape, labelled, and written to
`near/data/intents/synthetic/`. The same attacks also run against a fixed verifier as negatives.

## What it reproduces

The 2026-10-01 exploit works like this. A bridge token's `mt_batch_transfer_call` deposits about 98 entries into
intents.near: dust entries of amount `1` with a long token id, plus one real entry. The deposit asks for a
`Notify` to a receiver contract. That receiver returns a refund of `1e36` for every entry. It also already holds a
large balance of the dust token inside intents.near. So intents.near's `mt_resolve_deposit` burns `1e36` per dust
entry. Its burn log (37-digit amounts) outgrows the mint log (amount `"1"`) and passes the 16,384-byte log limit.
The resolve then panics and its state rolls back, so the receiver keeps the minted credit. The token sees the
failed callback and refunds the sender in full. The result is a ghost balance.

In the sandbox, at verifier v0.4.2:
- the mint log is 13,086 bytes; mainnet's was 13,087;
- the token's transfer log is 10,755 bytes; mainnet's was 10,756;
- `mt_resolve_deposit` fails with `refund event log would be too long`. On mainnet it failed with the host error
  `The length of a log message 16495 exceeds the limit 16384`; the deployed build differed slightly;
- the receiver keeps the credit, and the token refunds the sender in full.

`test_sandbox_e2e.py` asserts all of this. It also asserts that the fixed build rejects the deposit with
`too many tokens`.

## Layout

| File | What |
|---|---|
| `nearkeys.py` | Pure-stdlib ed25519 (RFC 8032), base58, and borsh `Transaction` encoding. The venv has no NEAR or ed25519 package, and `pyproject.toml` must not change. |
| `sandbox.py` | Starts and stops the `near-sandbox` node, a JSON-RPC client, signing accounts, and `sandbox_patch_state` for top-level names. |
| `world.py` | Deploys `intents.near` (the verifier under test), `omni.bridge.near` (bridged NEP-245 token), `usdt.bridge.near` (NEP-141), `wrap.near` (wNEAR), and receiver stubs. |
| `mt_token/` | A small NEP-245 token contract, Rust/near-sdk 5.24 (see "Deviations"). |
| `patches/v0.4.2-batch-limit.patch` | The fixed verifier: v0.4.2 plus the deposit batch limit from `b8bcf7dc`, which shipped in v0.4.3. |
| `scenarios.py` | Attack and benign families, with ground truth taken from contract state. |
| `fastnear_shape.py` | Converts an RPC `EXPERIMENTAL_tx_status` result into the FastNEAR record shape. |
| `generate.py` | CLI that runs the scenarios on worker threads and writes the gzip JSONL output. |
| `fixtures/` | Recorded sandbox responses, plus one real FastNEAR exploit record, used by the unit tests. |

## Reproduce

Run everything from the repo root.

**1. Sandbox binary.** The intents repo pins `near-sandbox = "0.3.4"`, whose `DEFAULT_NEAR_SANDBOX_VERSION` is
2.10.2. This is the same tarball that crate downloads. It does not use the 2.14.1 binary under `near/contract`.
```bash
mkdir -p ~/.near/near-sandbox-2.10.2 && cd /tmp && \
curl -sSfLO https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/Darwin-arm64/2.10.2/near-sandbox.tar.gz && \
tar xzf near-sandbox.tar.gz && cp Darwin-arm64/near-sandbox ~/.near/near-sandbox-2.10.2/ && cd -
# or point NEAR_SANDBOX_BIN_PATH at an existing binary
```
The tarball we used has sha256 `8e7a3c91d1fbcfdf0f693e0a65891ffeff20a8e887b9638a936fe4e276ccc547`.

**2. Wasm builds.** `INTENTS` is a clone of github.com/near/intents. `WASM` is where the optimized wasms go, set
with `INTENTS_SYN_WASM_DIR`. The default is `near/data/intents/synthetic/wasm` (gitignored). `INTENTS_V042_DIR` points at the
v0.4.2 worktree (default `near/data/intents/synthetic/intents-v042`), for the prebuilt `releases/fungible-token.wasm` and `releases/wnear.wasm`.
```bash
rustup toolchain install 1.86.0 --profile minimal -t wasm32-unknown-unknown
git -C $INTENTS worktree add ../intents-v042 6dad94cf8a9cf3083d9c1cf6c052ef8cdde0d473
cd $INTENTS/../intents-v042
RUSTUP_TOOLCHAIN=1.86.0 cargo build -p defuse --target wasm32-unknown-unknown --release --locked \
  --no-default-features --features=contract,imt        # sha256 180d5428...fd74 (1.6 MB)
RUSTUP_TOOLCHAIN=1.86.0 cargo build -p multi-token-receiver-stub --target wasm32-unknown-unknown --release \
  --locked --no-default-features
# fixed verifier: a copy of the v0.4.2 tree plus the batch-limit patch
rsync -a --exclude target --exclude .git ./ ../intents-v042-batchlimit/
(cd ../intents-v042-batchlimit && patch -p1 < $REPO/near/intents/synthetic/patches/v0.4.2-batch-limit.patch && \
 cd defuse && RUSTUP_TOOLCHAIN=1.86.0 cargo build --target wasm32-unknown-unknown --release --locked \
   --no-default-features --features=contract,imt)
# bridged MT token (Cargo.lock copied from v0.4.2 to pin near-sdk's dependencies for rustc 1.86)
(cd $REPO/near/intents/synthetic/mt_token && CARGO_TARGET_DIR=/tmp/mt_target RUSTUP_TOOLCHAIN=1.86.0 \
   cargo build --offline --target wasm32-unknown-unknown --release)
# wasm-opt (binaryen 116): shrinks defuse below the RPC body limit, and re-encodes rustc 1.86 output
# into a form protocol 82 accepts
wasm-opt -Oz --strip-debug target/wasm32-unknown-unknown/release/defuse.wasm -o $WASM/defuse-v0.4.2.wasm
wasm-opt -Oz ../intents-v042-batchlimit/target/wasm32-unknown-unknown/release/defuse.wasm \
  -o $WASM/defuse-v0.4.2-batchlimit.wasm
wasm-opt -Oz target/wasm32-unknown-unknown/release/multi_token_receiver_stub.wasm \
  -o $WASM/multi_token_receiver_stub.wasm
wasm-opt -Oz /tmp/mt_target/wasm32-unknown-unknown/release/synthetic_mt_token.wasm \
  -o $WASM/synthetic_mt_token.wasm
```

**3. Generate.**
```bash
.venv/bin/python -m near.intents.synthetic.generate --version v0.4.2 --attacks 700 --benign 700 --workers 8 --seed 7
.venv/bin/python -m near.intents.synthetic.generate --version v0.4.3-backport --attacks 200 --benign 150 \
  --workers 6 --seed 11 \
  --attack-families notify_refund_log_overflow,notify_refund_overask,notify_receiver_failure,callback_low_gas
```
Each run starts its own sandbox in `--work`. Setup takes about 30 seconds, and 1,400 transactions took 376 s on
8 workers.

The shipped data also has two exploit-focused batches, added with `--append`:
```bash
.venv/bin/python -m near.intents.synthetic.generate --version v0.4.2 --attacks 1000 --benign 300 --seed 21 \
  --attack-families notify_refund_log_overflow --append
.venv/bin/python -m near.intents.synthetic.generate --version v0.4.2 --attacks 700 --benign 0 --seed 33 \
  --attack-families notify_refund_log_overflow --append
```
The seed-21 batch ran before the first dust id was forced long, so only 17% of it overflowed. After that change
the seed-33 batch reached 60%.

**Generated data (2026-11-14).**

| Set | Transactions | Roles |
|---|---|---|
| v0.4.2 attacks | 2,400 | 706 `exploit` (all `notify_refund_log_overflow`, each with `ghost_credit` > 0, from 1e17 to 1.28e26 units), 1,694 `attempt` |
| v0.4.2 benign | 992 | all `benign` |
| fixed, v0.4.3-backport | 349 | 200 attack `attempt`, 149 `benign`; no ghost credit at all |

Eight benign wNEAR records (and one in the fixed set) were removed after generation. A generator bug sent a
negative `ft_transfer_call` amount in them; the bug is fixed. One run attempt failed transiently inside
`build_world` (`no access key for intents.near`). The node sometimes drops a `sandbox_patch_state` call, so
`Chain.patch_account` now re-sends the patch until the key is visible. The e2e test passed 3 out of 3 runs after
that change.

**4. Tests.**
```bash
.venv/bin/python -m unittest near.intents.synthetic.test_nearkeys near.intents.synthetic.test_fastnear_shape \
  near.intents.synthetic.test_scenarios
INTENTS_SANDBOX_E2E=1 .venv/bin/python -m unittest near.intents.synthetic.test_sandbox_e2e   # ~30 s, real sandbox
```

## Output

| File | Contents |
|---|---|
| `near/data/intents/synthetic/attacks.jsonl.gz` | Attack transactions against v0.4.2 |
| `near/data/intents/synthetic/benign.jsonl.gz` | Benign transactions against v0.4.2 |
| `near/data/intents/synthetic/fixed_v0.4.3-backport.jsonl.gz` | Both labels, against the fixed verifier |
| `near/data/intents/synthetic/summary_<version>.json` | Counts per label, family and role; scenario errors |

Each line is one FastNEAR-shaped transaction (`transaction`, `execution_outcome`, `receipts[]`, `data_receipts[]`)
plus `_meta`:

```json
{"source": "sandbox", "label": "attack|benign", "role": "exploit|attempt|benign",
 "campaign": "sandbox:<family>", "attack_family": "...", "benign_family": "...", "variant": {...},
 "outcome": {"ghost_credit": "...", "resolve_failed": true, "failures": [...], ...},
 "verifier_version": "v0.4.2", "near_sandbox": "2.10.2", "fetched_at": "...", "worker": 0,
 "data_receipts": "reconstructed ..."}
```

`role` comes from state, never from the tx status:
- `exploit`: intents.near kept credit for the receiver that the token contract does not back (`ghost_credit > 0`);
- `attempt`: the attack shape ran but did not gain anything.

**Attack families.**

| Family | What it does | Expected result |
|---|---|---|
| `notify_refund_log_overflow` | The October exploit, varied: entry count, dust id length (60–127), 1–3 distinct dust ids, dust amount, refund size (1e29–1e37), order (dust first, main first, interleaved), `ReturnValue` vs `ReturnValues`, notify `min_gas`. The entry count is sampled around the point where the burn log passes the limit, so about 70% overflow and the rest are near misses with the same shape. | Overflows are `exploit`. Near misses and out-of-gas runs are `attempt`. |
| `notify_refund_overask` | Small batches (1–10 entries); the receiver asks for more refund than it was sent (`MaliciousRefund`, a huge `ReturnValue`, or `ReturnValues` above the amounts). | `attempt` |
| `notify_receiver_failure` | The receiver panics, returns 100 kB–3 MB, or returns the wrong number of values. | `attempt` |
| `callback_low_gas` | Notify deposits with too little gas, 20–150 TGas total, or a huge notify `min_gas`; the April out-of-gas pattern. | `attempt` |
| `direct_private_call` | A signer calls `*_resolve_*` directly. | `attempt` |
| `admin_probe` | A non-role account calls `upgrade`, `acl_*`, `pa_pause_feature`, `set_fee*`, `add_relayer_key`, `ft_force_withdraw`, `mt_force_transfer`, `force_*`, `invalidate_salts`, `cleanup_nonces`; the May fuzzing pattern. | `attempt` |
| `token_spoof_direct_on_transfer` | A signer calls intents.near's `ft_on_transfer` / `mt_on_transfer` itself, posing as a token. One variant sends the overflow payload this way. | `attempt` |

**Benign families.**
- `mt_deposit`: 1–10 tokens, with `msg` empty, an account id, or JSON.
- `mt_deposit_notify`: the receiver accepts, refunds everything, refunds part, or returns 0.
- `ft_deposit`: includes Notify to a stub.
- `wnear_deposit`: one transaction with `storage_deposit?` + `near_deposit` + `ft_transfer_call`.
- `ft_withdraw`, `mt_withdraw`.
- `intents_mt_transfer`.
- `execute_intents`: a relayer submits NEP-413-signed `transfer`, multi-transfer, or `ft_withdraw` intents.

## Deviations from mainnet (read before training on this)

1. **Gas cap.** The pinned sandbox runs protocol 82, which caps a transaction at 300 TGas. The exploit used
   1 PGas. Through a defuse-style token that reserves `8 + 2·n` TGas for its resolve, a 98-entry deposit cannot
   fit. So `omni.bridge.near` runs `mt_token/`, a lean NEP-245 token that reserves a flat 15 TGas for
   `mt_resolve_transfer` and passes the rest to `mt_on_transfer`.

   Its refund semantics match NEP-245 and HOT Omni:
   - it refunds `min(requested, amount)` per entry;
   - it refunds every amount when the receiver's promise fails.

   Its gas numbers, method layout and logs are not HOT's. Do not use absolute gas as a feature. About 100 entries
   is the most that fits; above 104 the deposit runs out of gas.
2. **Fixed version.** The fixed verifier is v0.4.2 plus the batch limit (≤ 10 tokens per deposit). That is the
   change in `b8bcf7dc`, released as v0.4.3 and deployed on 2026-10-02. The requested fixed commit `16d04f6e`,
   "remove notifications on deposits", needs rustc ≥ 1.95. Its wasm uses bulk-memory, and sandbox 2.10.2 rejects
   the deploy with `CompilationError: PrepareError: Deserialization`. We tried an MVP rebuild with nightly
   `-Zbuild-std`; it failed because that nightly has no `rust-src` installed. So 16d04f6e is not covered.
3. **Data receipts.** The node's RPC does not return data receipts. `data_receipts` are rebuilt from
   `output_data_receivers`, with the value taken from the final status of the promise chain. Their `receipt_id`
   is a stand-in (sha256 of the `data_id`). `index` and `receipt_index` are positions within the transaction,
   not within the chunk.
4. **Accounts and blocks.** Account names are chosen to look like mainnet roles: `intents.near`,
   `omni.bridge.near` (the same length as `v2_1.omni.hot.tg`), `usdt.bridge.near`, `wrap.near`, and implicit
   hex accounts for users, attackers, relayers and receivers. Block heights and timestamps are the sandbox's,
   with about 100 ms blocks.
5. **Verifier error text.** On v0.4.2 the resolve fails with the contract's own `refund event log would be too
   long` check. Mainnet showed the host's `length of a log message ... exceeds the limit`. Both are a
   `mt_resolve_deposit` Failure with the credit kept.
6. **Benign traffic.** The benign set is only what this harness can drive. It does not cover solver `token_diff`
   swaps, PoA bridge `ft_deposit` minting, HOT `mt_batch_transfer_call` from real wallets, storage/near
   withdrawals, and so on. Use it for the PLAN's domain check, not as a replacement for mainnet normals.
