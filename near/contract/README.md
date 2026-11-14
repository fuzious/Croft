# NEAR Security Oracle: on-chain contracts

Two near-sdk 5.30 contracts and their sandbox tests:

- **`security_oracle`**: attesters (the oracle service's operator keys) publish a verdict per NEAR account
  (`allow` / `warn` / `block`, risk score in basis points, scored code hash, expiry). Anyone can report an account
  with evidence; an attester confirms (the account becomes blocked) or dismisses the report. A blocked account
  always reads as `block` from `get_verdict`, whatever was attested.
- **`guarded_router`**: the on-chain backstop for AI agents. A human funds a balance for an agent account; the agent
  holds only a function-call key for `guarded_router` / `pay`. `pay` debits the balance and the daily allowance,
  asks the oracle (`get_verdict` and `is_blocked`, in parallel), and transfers in a private callback only when the
  verdict is `allow`, unexpired, and the receiver is not blocked. Any other outcome restores the debit and logs a
  NEP-297 `payment_refused` event with the reason. A prompt-injected agent that skips the off-chain wrapper is
  still stopped here.

## Build and test

Toolchain: `rust-toolchain.toml` pins Rust **1.95.0** with `wasm32-unknown-unknown` (rustup installs it on first
use). near-sdk 5.30 declares protocol version 85, so cargo-near accepts the bulk-memory opcodes newer rustc emits;
with near-sdk ≤ 5.27 you would need Rust ≤ 1.86.

```bash
cargo +1.95.0 install cargo-near --version 0.23.0 --locked   # once, a few minutes

cd near/contract
cargo test                 # builds both wasm files with cargo-near-build, runs the near-workspaces sandbox tests
(cd security_oracle && cargo near build non-reproducible-wasm)   # -> target/near/security_oracle/security_oracle.wasm
(cd guarded_router  && cargo near build non-reproducible-wasm)   # -> target/near/guarded_router/guarded_router.wasm
cargo clippy --target wasm32-unknown-unknown -p security_oracle -p guarded_router
```

`cargo test` at this root runs only `sandbox_tests` (the workspace's default member): the contracts themselves
compile only for wasm. The first run downloads the `near-sandbox` binary (done by the `near-sandbox` crate's build
script) and compiles the contracts; later runs reuse both. The tests deploy the real wasm on a local sandbox; nothing
is mocked.

Tests (18): oracle access control and attester management, verdict validation, the 7-day expiry cap, a removed
attester's verdicts no longer served (its confirmed blocks still are), report storage deposit and refund, confirm →
blocked (overrides an `allow`), dismiss, owner-only unblock, NEP-330 metadata; router allow path transfers, block /
warn / no verdict / removed attester's `allow` / confirmed report / expired verdict refused with balance and
allowance rolled back, transfer to a missing account rolled back, daily limit, non-agent callers, low gas, overdraft,
owner-only deposit / limit / withdraw, private callbacks, and that the agent's function-call key cannot transfer
NEAR, call another router method, call another contract, or attach a deposit.

## Deploy (testnet)

Not yet run against testnet; these are the standard `near` CLI (near-cli-rs) and `cargo near` forms.

```bash
near account create-account sponsor-by-faucet-service oracle-<you>.testnet autogenerate-new-keypair save-to-keychain network-config testnet create
cd security_oracle && cargo near deploy build-non-reproducible-wasm oracle-<you>.testnet \
  with-init-call new json-args '{"owner_id":"<you>.testnet","attesters":["attester-<you>.testnet"]}' \
  prepaid-gas '30 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
cd ../guarded_router && cargo near deploy build-non-reproducible-wasm router-<you>.testnet \
  with-init-call new json-args '{"oracle_id":"oracle-<you>.testnet"}' \
  prepaid-gas '30 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
```

Give the agent its key (from the human's full-access key on `agent.<you>.testnet`):

```bash
near account add-key agent.<you>.testnet grant-function-call-access --allowance '0.25 NEAR' \
  --contract-account-id router-<you>.testnet --function-names 'pay' autogenerate-new-keypair save-to-keychain \
  network-config testnet sign-with-keychain send
```

## Methods

### `security_oracle`

| Method | Kind | Who | Notes |
|---|---|---|---|
| `new(owner_id, attesters: [AccountId])` | init | deployer | |
| `submit_verdict(account_id, code_hash, verdict, score_bps, reasons_hash, expires_at_ns)` | change | attester | `verdict`: `"allow"\|"warn"\|"block"` (capitalised accepted); `score_bps` ≤ 10000; `reasons_hash` 64 hex chars (sha256 of the reasons JSON); `expires_at_ns` (U64 string) must be in the future and at most 7 days ahead (`expiry too far` otherwise); replaces the previous verdict |
| `report(account_id, evidence_url, evidence_sha256) -> U64` | change, payable | anyone | attach ≥ the report's storage cost (a few hundred bytes at 10¹⁹ yocto/byte, i.e. a few milliNEAR; 0.01 NEAR is safe); excess refunded; returns report id; stored `pending` |
| `confirm_report(report_id)` | change | attester | `pending` → `confirmed`; the account becomes blocked |
| `dismiss_report(report_id)` | change | attester | `pending` → `dismissed` |
| `add_attester(attester)` / `remove_attester(attester)` | change, 1 yocto | owner | removing an attester stops `get_verdict` serving the verdicts it attested (they read as none until it is re-added or another attester re-attests); blocks it confirmed stay |
| `unblock(account_id)` | change, 1 yocto | owner | lifts a block; report history is kept |
| `set_owner(owner_id)` | change, 1 yocto | owner | |
| `get_verdict(account_id) -> Option<Verdict>` | view | | `{code_hash, verdict, score_bps, reasons_hash, attested_at_ns, expires_at_ns, attester}`; blocked → `block`, score 10000, never expires, `reasons_hash` = evidence sha256, even if the confirming attester was removed; otherwise `null` when the verdict's attester is no longer an attester |
| `is_blocked(account_id) -> bool` | view | | |
| `get_block(account_id) -> Option<Block>` | view | | `{report_id, evidence_sha256, confirmed_by, confirmed_at_ns}` |
| `get_report(report_id)`, `get_reports(account_id, from_index?, limit?)` | view | | `get_reports` returns ≤ 50 per call, oldest first |
| `get_owner()`, `get_attesters()`, `is_attester(account_id)` | view | | |
| `contract_source_metadata()` | view | | NEP-330 (link to this repo; standards nep330, nep297) |

Events (NEP-297, standard `security_oracle`): `verdict_submitted`, `report_filed`, `report_confirmed`,
`report_dismissed`, `unblocked`, `attester_added`, `attester_removed`.

### `guarded_router`

| Method | Kind | Who | Notes |
|---|---|---|---|
| `new(oracle_id)` | init | deployer | the oracle is fixed; the router has no admin |
| `deposit(agent_id, daily_limit?: U128)` | change, payable | agent's owner | first deposit registers the agent: the caller becomes owner, `agent_id` must be a direct sub-account of the caller (anti-squatting), `daily_limit` required, storage cost taken from the deposit |
| `set_limit(agent_id, daily_limit: U128)` | change, 1 yocto | owner | |
| `withdraw(agent_id, amount: U128)` | change, 1 yocto | owner | needs ≥ 20 Tgas; balance restored if the transfer fails |
| `pay(receiver_id, amount: U128) -> bool` | change, **not payable** | the agent (predecessor) | needs ≥ 60 Tgas (100 Tgas recommended); panics on unknown caller, over the daily limit, insufficient balance, paying the router; otherwise returns `true` on transfer, `false` on refusal |
| `on_verdict`, `on_transfer`, `on_withdraw` | `#[private]` callbacks | the router itself | |
| `get_agent(agent_id) -> Option<Agent>` | view | | `{owner_id, balance, daily_limit, spent_today, day}` (yoctoNEAR strings) |
| `get_oracle()` | view | | |

`payment_refused` reasons: `verdict_block`, `verdict_warn`, `no_verdict`, `verdict_expired`, `receiver_blocked`,
`oracle_call_failed`, `oracle_bad_response`. Other events (standard `guarded_router`): `agent_funded`,
`limit_set`, `payment_sent`, `payment_failed` (transfer bounced, debit restored), `withdrawn`, `withdraw_failed`.

## How the router avoids the taxonomy's bugs

| Class | Handling |
|---|---|
| `non_private_callback` | all callbacks are `#[private]` |
| `unhandled_promise_result` | both oracle results read with a length cap; failed, malformed, unknown or missing results refuse and restore the debit; the transfer has its own callback that restores the debit if it bounced |
| `async_reentrancy` | balance and daily allowance are debited *before* the oracle call, so concurrent `pay` calls cannot double-spend; callbacks only restore |
| `missing_access_control` / `signer_auth` | `predecessor_account_id` everywhere; owner checks on `set_limit` / `withdraw`; agent = predecessor on `pay` |
| `missing_one_yocto` | `set_limit`, `withdraw` and the oracle's owner methods require exactly 1 yoctoNEAR |
| `unsafe_arithmetic` | `checked_*` on all amounts, `overflow-checks = true` in release |
| `storage_staking` | agent registration and reports are paid by the caller, measured with `storage_usage()` |
| `gas_dos` | callbacks get static gas; `pay` refuses up front with too little prepaid gas; report listing is paginated |
| `unguarded_upgrade` | neither contract has an upgrade path |

## Limits (be aware)

- The router cannot read another account's code hash on chain, so it does not compare the verdict's `code_hash` with
  the receiver's current code. Attesters must re-attest (or let verdicts expire) when a receiver redeploys; short
  expiries are the defence.
- Attester methods take no deposit so the oracle service can sign with a function-call key; a leaked attester key
  can publish verdicts until the owner removes it. Removing it revokes those verdicts at once (`get_verdict` ignores
  verdicts from non-attesters, so the router refuses with `no_verdict`), and no verdict can be set to last more than
  7 days. Reports the key confirmed stay confirmed; the owner lifts wrong blocks with `unblock`.
- The 1 yoctoNEAR attached to owner calls and report storage deposits stay in the contracts.
- `warn` is refused on chain: the router has no human in the loop. The off-chain agent wrapper asks the human and can
  pay a `warn` receiver from the human's own key instead.
- Daily limit days are UTC block-timestamp days (`block_timestamp / 86400 s`), not rolling 24 h windows.
- Not audited. Tested only on the local sandbox.
