# Optional sandbox reproduction

This research harness reproduces retained credit after a failed deposit callback. It is **not needed for the
hackathon demo** and does not train the shipped detector. [Results](../reports/RESULTS.md)

| Verifier | Expected outcome |
|---|---|
| v0.4.2, commit `6dad94cf8a9cf3083d9c1cf6c052ef8cdde0d473` | Callback fails; credit retained; sender refunded |
| v0.4.2 + batch-limit patch | Oversized deposit rejected; no ghost credit |

## Setup

Use near-sandbox **2.10.2** (`NEAR_SANDBOX_BIN_PATH`), Rust **1.86.0**, and Binaryen **116**.
This differs from the newer sandbox used for the agent/router demo.
Set `REPO` to this repository and `INTENTS` to a local clone of `near/intents`. Create the WASM output directory
and set `INTENTS_SYN_WASM_DIR` to it; set `WASM` to that same path for the commands below.

<details>
<summary>Build the required WASM artifacts</summary>

`INTENTS` is a clone of github.com/near/intents. `WASM` is where the optimized wasms go, set
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
</details>

## Run

From this repository's root, with `INTENTS_V042_DIR` pointing to the v0.4.2 worktree:

```bash
INTENTS_SANDBOX_E2E=1 uv run python -m unittest near.intents.synthetic.test_sandbox_e2e
uv run python -m near.intents.synthetic.generate --version v0.4.2 --attacks 700 --benign 700 --seed 7
```

Outputs go to `near/data/intents/synthetic/`. An `exploit` label requires positive unbacked credit measured from
contract state; an attempted attack without gain is an `attempt`. Recorded fixtures support ordinary unit tests.

## Limits

- A custom token fits the sandbox's 300 TGas cap; mainnet used 1 PGas. Gas, methods and logs differ from HOT Omni.
- The fixed build backports the ≤10-token batch limit; it does not test the later notification-removal fix.
- RPC omits data receipts; the harness reconstructs them with synthetic IDs and transaction-local indexes.
- Accounts, timestamps and blocks are synthetic. Sandbox error text differs from mainnet.
- Benign traffic lacks solver swaps and some real bridge flows; it cannot replace mainnet negatives.
- The synthetic classifier was rejected: it added no detections and raised 80 normal transactions to high.
