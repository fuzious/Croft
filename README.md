# NEAR Protocol Security Agent

**Inspect a transaction. Find the attack pattern. See the evidence.**

A protocol investigation agent for NEAR: submit a mainnet transaction hash or scan an account's recent activity.
It reads receipt graphs, reconciles deposit/refund events, and connects earlier activity to explain what looks suspicious.

[Run it](near/README.md) · [Intents evidence](near/intents/reports/RESULTS.md) · [API reference](http://localhost:8000/docs)

```mermaid
flowchart LR
    T[Transaction hash] --> F[Fetch receipts and logs]
    P[Protocol or account] --> S[Scan recent Intents activity]
    S --> F
    F --> C{Coverage and completeness}
    C --> R[Receipt rules + anomaly model]
    C --> A[Deposit / refund / retained credit]
    H[Earlier related transactions] --> W[Bounded history checks]
    R --> E[Assessment + evidence + limitations]
    A --> E
    W --> E
    E --> O[Operator investigates]
    O -. optional response .-> B[Evidence report or account policy]
```

## The result

| Assessment | What it means |
|---|---|
| **High-severity pattern** | A high-severity known attack pattern was observed; investigate the evidence |
| **Suspicious** | Anomalous behavior or medium-severity rules need review |
| **No known pattern** | Nothing reached an alert threshold in the available, supported data; **not proof of safety** |
| **Inconclusive / unsupported** | Evidence is incomplete or the transaction is outside calibrated coverage |

You can submit **any well-formed NEAR mainnet transaction hash**. The current detector is calibrated on **NEAR
Intents**, not every NEAR protocol. Unsupported transactions are identified explicitly. It inspects completed
transactions; it does not simulate pending transactions or automatically stop an exploit.

## What it looks for

| Evidence | Why it matters |
|---|---|
| Failed resolve callback | Refund or deposit accounting may not have completed |
| Log near the 16 KB limit | Callback execution may fail during bookkeeping |
| Credit retained after a refund | Internal credit may no longer be backed by tokens |
| Out-of-gas callbacks, direct private/admin calls | Suspicious execution paths or probing |
| Earlier callback failures and related withdrawals | Links relevant activity without treating a shared relayer as an attacker |

The explanation includes rule hits, exact token amounts, linked history, receipt coverage and model identity.
Accounting checks reconcile successful **events**, not independent balance proofs. Only linked FT/MT deposits
are covered; missing or ambiguous evidence stays inconclusive.
A protocol scan scores up to **20 Intents transactions among an account's 40 most recent**, cached five minutes.
This is a bounded scan, not continuous monitoring or a complete account audit.

## Attack families

The taxonomy adapts the value-flow and grouped-evaluation approach from `main` to NEAR's asynchronous execution.
A supported pattern covers part of a family, not every attack in it.

| Family | Current evidence |
|---|---|
| Callback accounting | Deposit, refund and surviving credit events |
| Access-control abuse | Direct private/admin calls and repeated rejected probes |
| Token spoofing | Some direct receiver probes; asset authenticity needs a registry |
| Resource exhaustion | Callback gas, log and return-value failures |
| Async state race / reentrancy | Needs interleaved execution and protocol state |
| Replay / signature abuse | Needs signature, nonce and historical key verification |
| Oracle / price manipulation | Needs trusted prices and valuation rules |
| Arithmetic / rounding | Needs contract arithmetic and state deltas |
| Share / claim accounting | Needs share supply and redemption state |
| Protocol accounting logic | Needs a protocol-specific state model |
| Bridge validation | Needs source-chain proofs and bridge state |

[Category definitions and sources](near/intents/fixtures/attack_taxonomy.json).
Training keeps real attacks, controlled sandbox attempts and unlabelled traffic separate; held-out method/mode
variants and whole-family tests are reported separately from mainnet measurements.

## Try it

```bash
# One-time setup: near/README.md
uv run uvicorn near.service.app:app --port 8000
# Open http://localhost:8000/demo/

# Deterministic evidence replay; no network or keys
uv run python -m near.demo.replay
```

| Demo input | What to show |
|---|---|
| October exploit preset | High-severity callback, log and credit evidence |
| Normal deposit preset | No known attack pattern, with coverage shown |
| Known missed token-spoof preset | A real detection limitation, clearly labelled |
| `intents.near` or October exploiter scan | Recent transactions; open any row for the full analysis |

## Evidence, not a guarantee

![Retrospective Intents campaign detections.](docs/assets/results.svg)

**23/23** October exploit transactions flagged high; one known technique repeated by one actor.
**0/7,400** clean normal test transactions flagged high (95% upper bound: 0.052%). Rules were developed after
seeing the campaigns. The anomaly model added no campaign detections and produced **84/7,400 medium alerts**.
[Detailed evaluation](near/intents/reports/RESULTS.md)

## Optional integrations

- **Rust source analysis:** inspect contract code alongside transaction evidence. Most real bugs are missed;
  this is a supporting signal. [Code-model evidence](near/model/reports/RESULTS.md)
- **On-chain response:** an operator can review evidence, publish an account verdict or confirm a report.
  The supplied router enforces that policy on future native NEAR payments routed through it. It cannot undo the
  inspected transaction, pause an arbitrary protocol, or turn a transaction label directly into an account block.
  [Contracts](near/contract/README.md) · [Response client](near/agent/README.md)

<details>
<summary>Project provenance</summary>

- **Pre-hackathon code:** the EVM security oracle (first committed 2026-10-15) predates the hackathon and lives on
  the `main` branch. `near/` reuses its method (grouped CV, frozen model with hashes, sealed test scored once) but
  none of its code. Everything under `near/` was built during the hackathon. The 2026-11-14 commit f567294 in
  this branch's history is an EVM state sync, not part of the submission.
- **AI-generated code:** most code, data tooling and docs under `near/` were written with Claude Code, directed and
  reviewed by the author. Label re-checks and fix-commit triage were also done by AI agents.

</details>

[Setup & API](near/README.md) · [License: BUSL-1.1](LICENSE)
