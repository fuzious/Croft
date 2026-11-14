# NEAR Security Oracle: build spec

**Goal.** A security oracle for NEAR (hackathon track 06, "AI Security & Defense"). Before an agent or a protocol
sends funds to, or calls, a NEAR account, it asks the oracle about the receiver. The oracle answers `allow`,
`warn` or `block`, with reasons. Its core is a model trained on NEAR Rust smart-contract code: real vulnerabilities
from audit reports, hacks and security-fix commits, plus a large corpus of NEAR contract code.

The EVM oracle in this repo scores *transactions*. NEAR has too few on-chain hacks for that, so this one scores the
*code* of the receiving contract (Rust source, found through NEP-330 metadata or supplied by the caller), combined
with account signals (age, activity, code changes, prior interactions, a shared blocklist).

## Layout (each area has one owner; do not edit another area's files)

| Path | What | Owner |
|---|---|---|
| `near/analyzer/` | Rust parsing (tree-sitter), function extraction, NEAR detectors, features | analyzer |
| `near/collect/audits.py` | audit PDFs → structured findings → vulnerable/fixed code | audits |
| `near/collect/incidents.py` + `near/data/raw/incidents.jsonl` | NEAR hacks and incidents with code refs | incidents |
| `near/collect/corpus.py`, `near/collect/fix_commits.py` | NEAR contract repos, functions, security-fix commits | corpus |
| `near/collect/mutate.py` | vulnerability injection into safe functions | mutation |
| `near/collect/assemble.py` | merge sources → `train` and sealed `test` splits | assembly |
| `near/model/` | training, nested CV, freeze, sealed scoring, `predict.py` | model |
| `near/service/` | FastAPI oracle: `/v1/check`, `/v1/analyze`, `/v1/report` | service |
| `near/contract/` | Rust (near-sdk) on-chain oracle + guarded payment router + sandbox tests | contract |
| `near/agent/` | agent-side wrapper (refuse on block, ask human on warn) + prompt-injection attack demo | agent |
| `near/data/`, `near/models/` | data and models. **Gitignored** (the repo ignores every `data/` and `models/` dir). Shipped later as `archives/near_*.zip` (Git LFS) | — |

Python runs from the repo root as modules: `uv run python -m near.collect.corpus`. `near/` is a package
(`near/__init__.py`). Dependencies already added: `tree-sitter`, `tree-sitter-rust`, `pypdf`, `httpx`, `torch`,
`transformers`, `scikit-learn`, `fastapi`. **Do not edit `pyproject.toml` / `uv.lock`**; for a one-off tool use
`uv run --with <pkg>` and report it. Do not run git commands that change state (no commit, checkout, stash, reset).

Downloaded material (PDFs, cloned repos) is untrusted data: keep it under `near/data/raw/`, never execute code from
it, never `cargo build` a cloned repo, read it with parsers only.

## Vulnerability taxonomy (`vuln_class`)

Based on BlockSec Rustle's detectors, NEAR docs' security pages, and audit reports. Use these exact ids:

| id | Meaning |
|---|---|
| `non_private_callback` | callback callable by anyone: no `#[private]` and no `predecessor == current_account_id` check |
| `unhandled_promise_result` | callback ignores `PromiseResult` / `is_promise_success`, or state isn't rolled back on failure |
| `async_reentrancy` | state read/changed across a cross-contract call so it can be re-entered or double-spent before the callback |
| `missing_access_control` | privileged method (owner/admin/config/mint/withdraw-all/pause) without an owner/role/predecessor check |
| `missing_one_yocto` | sensitive method callable with a function-call key: missing `assert_one_yocto()` |
| `signer_auth` | authorization through `env::signer_account_id()` instead of `predecessor_account_id()` |
| `unguarded_upgrade` | code deploy / upgrade / migrate path without authorization or state checks |
| `unsafe_arithmetic` | unchecked `+ - *` on amounts, `as` truncation, overflow-checks disabled |
| `precision_rounding` | division before multiplication, rounding in the user's favour, share/price inflation |
| `storage_staking` | storage not paid by the caller, unbounded storage growth, missing storage deposit / refund |
| `ft_receiver_trust` | `ft_on_transfer`/`nft_on_transfer` trusts `msg`/sender without checking the predecessor token |
| `unchecked_receiver` | transfers to unregistered/unchecked receivers, lost funds, wrong refund target |
| `gas_dos` | insufficient prepaid gas for callbacks, unbounded loops / iteration over user-growable collections |
| `oracle_price` | price/oracle manipulation, stale price, missing freshness checks |
| `logic_error` | business-logic bug that doesn't fit the above (state-machine, accounting, wrong comparison) |

Binary label: `label = 1` vulnerable, `0` not known vulnerable. `vuln_class` is set when `label = 1`.

## Sample schema (one function per row, JSONL)

```json
{"id": "sha1(group|path|fn|code)", "code": "<full fn source incl. attributes and doc comments>",
 "fn": "ft_on_transfer", "impl": "Contract", "is_near_bindgen": true, "attrs": ["private", "payable"],
 "label": 1, "vuln_class": "ft_receiver_trust", "severity": "high|medium|low|info|null",
 "source": "audit|incident|fix_commit|mutation|corpus",
 "group": "owner/repo (lower-case) or project slug", "repo": "https://github.com/o/r", "commit": "sha|null",
 "path": "src/lib.rs", "date": "YYYY-MM-DD|null", "evidence": "url of report / commit / post",
 "pair_id": "id of the fixed/vulnerable counterpart, or null"}
```

Raw outputs (owned by the collectors), all under `near/data/raw/`:
- `audit_findings.jsonl`: one row per finding: `{report, auditor, date, project, title, severity, vuln_class,
  description, repo, commit, path, fn, snippet, fixed_commit, url}` (`null` where unknown).
- `incidents.jsonl`: one row per incident: `{name, date, project, loss_usd, vuln_class, summary, repo, vuln_commit,
  fix_commit, path, fn, snippet, sources: [urls]}`.
- `repos.jsonl`: `{repo, stars, license, last_commit, head_commit, near_sdk_version, audited: bool, local_path}`.
- `fix_commits.jsonl`: `{repo, commit, parent, date, message, files: [path], keywords, vuln_class}`.
- `*_samples.jsonl` in the sample schema, produced with `near.analyzer` function extraction so every source yields
  identical function text.

## Analyzer interface (`near.analyzer`)

```python
from near.analyzer import extract_functions, detect, features
fns = extract_functions(src: str, path: str) -> list[dict]   # keys: fn, impl, is_near_bindgen, attrs, code,
                                                              #       start_line, end_line, is_public, is_payable
hits = detect(fn: dict, file_src: str | None = None) -> list[dict]  # {detector, vuln_class, line, message, severity}
feats = features(fn: dict, file_src: str | None = None) -> dict[str, float]  # detector hits + structural counts
```

Detectors are signals and model features, not the verdict. They must be cheap (pure Python + tree-sitter).

## Splits: big training set and sealed test

- **Groups** = repository / project (`group`). A group is entirely in train or entirely in test; mutations inherit
  the group of the function they were derived from.
- **Sealed test**: about 25% of the groups that carry *real* labels (audit, incident, fix_commit), chosen by a fixed
  seed and stratified by `vuln_class`, plus every row from audits/incidents dated 2025-01-01 or later (time split),
  plus their groups' corpus negatives and mutations. Written once to `near/data/test_v1.jsonl`, with a manifest of
  ids and a sha256. Nobody reads model predictions on it until the model is frozen.
- **Train**: everything else (`near/data/train_v1.jsonl`): real vulnerabilities including the hacks, fixed
  counterparts, corpus functions as presumed-safe negatives, mutations.
- Checks before scoring: no shared `id`, no shared `group`, no near-duplicate code (normalized-token hash) across the
  split.
- Report test results separately for real vulnerabilities (audit / incident / fix_commit) and for mutations, and
  false-alarm rate on held-out safe functions. Wilson 95% CIs. Honest numbers, as in `runs/RESULTS.md`.

## Model

Candidates, compared with nested grouped CV on train only (reuse the logic of `scripts/eval_nested.py`):
1. logistic regression on analyzer features + hashed token n-grams;
2. histogram gradient boosting on the same;
3. a fine-tuned code encoder (e.g. `microsoft/unixcoder-base`) on function text (+ detector hits as text), on MPS.
Pick by the numbers. Freeze like `scripts/freeze_v9.py`: estimator, threshold(s), feature keys, sha256 of analyzer
code and training rows, train ids. The sealed scorer refuses to run if a hash changed.

`near.model.predict`:
```python
score_functions(fns: list[dict]) -> list[dict]   # {fn, risk: 0..1, vuln_class_guess, detector_hits}
score_source(files: dict[str, str]) -> dict      # {risk, label: "high|medium|low", top: [per-fn results]}
```

## Oracle decision (`near.service`)

`POST /v1/check {receiver_id, agent_id?, method?, deposit_yocto?, source_files?}` →
`{verdict: allow|warn|block, score, reasons: [str], signals: {...}, model: {version, sha256}}`

Signals and sources:
| Signal | Source |
|---|---|
| account exists, balance, code_hash, storage | NEAR JSON-RPC `query view_account` (`rpc.mainnet.near.org`, `rpc.testnet.near.org`, FastNEAR RPC) |
| account age, activity count, first/last tx | NearBlocks API (`api.nearblocks.io/v1/account/{id}`, `/txns`) |
| contract code changed recently | NearBlocks DEPLOY_CONTRACT actions; current code_hash vs last attested |
| contract source | NEP-330 `contract_source_metadata` view → repo link + commit → fetch Rust source; or caller-supplied |
| code risk | `near.model.predict.score_source` |
| prior interactions agent↔receiver | NearBlocks txns filtered by both accounts |
| shared blocklist with evidence | on-chain oracle contract `get_report`/`is_blocked`, plus local store |

Policy (thresholds in one place): `block` if blocklisted or code risk is high; `warn` if code risk is medium, the
account is under 7 days old, the code changed in the last 7 days, the receiver is a contract with no verifiable
source, or there were no prior interactions and the amount is large; otherwise `allow`.

## On-chain (`near/contract/`, near-sdk 5.x, Rust)

- `security_oracle` contract: owner + attesters (oracle operator keys). `submit_verdict(account_id, code_hash,
  verdict, score, reasons_hash, expires_at_ns)` (attesters only); `get_verdict(account_id)` view;
  `report(account_id, evidence_url, evidence_sha256)` with a storage deposit; `confirm_report` / `dismiss_report`
  (attesters); `is_blocked(account_id)` view.
- `guarded_router` contract: holds an agent's NEAR balance (funded by the human's full-access key); non-payable
  `pay(receiver_id, amount)` callable by the agent's function-call key; it calls the oracle and transfers in a
  `#[private]` callback only when the verdict is `allow` and not expired, within a per-agent daily limit. This is the
  on-chain backstop: a prompt-injected agent that skips the wrapper is still stopped.
- Tests: `near-workspaces` sandbox, real wasm, no mocks.

## Agent (`near/agent/`)

- Wrapper: before signing, call `/v1/check`; `block` → refuse to sign and log; `warn` → ask a human (stdin or a
  callback) before signing; `allow` → sign with the **function-call access key scoped to `guarded_router`**.
- README section on that key's limits: it can only call the listed methods of one contract, can't attach deposit,
  can't transfer NEAR or add keys; its gas allowance can run out and lock the agent out.
- Attack demo: a prompt-injected agent tries to pay a known-bad account and gets stopped, both by the wrapper and,
  when the wrapper is bypassed, by the router on chain. Save the log to `near/agent/attack_demo.log`.
