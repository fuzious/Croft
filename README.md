# Security Oracle

Security Oracle investigates **NEAR Intents** transactions: submit a mainnet transaction hash or scan an
account's recent activity. It reads receipt graphs, reconciles deposit/refund events, and connects earlier activity
to explain what looks suspicious.

[Run it](near/README.md) · [Intents evidence](near/intents/reports/RESULTS.md) ·
[API reference](http://localhost:8000/docs) (after running locally)

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

You can submit **any well-formed NEAR mainnet transaction hash**. The detector is calibrated on **NEAR
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

## Evidence at a glance

The **accounting check** reconciles deposit, refund and surviving credit events. Against recorded sandbox
contract state and real case labels (checked-in report; the full input datasets are not bundled):

| Evidence set | High accounting findings |
|---|---:|
| Sandbox: measured credit defects | **712 / 712** |
| Sandbox: other unpatched executions | **0 / 2,953** |
| Sandbox: patched verifier | **0 / 349** |
| Real exploits: October transactions, one actor, one technique | **23 / 23** |
| Sampled historical normals | **0 / 100,098** |

Of the sandbox rows without a finding, 1,849 / 2,953 unpatched and 109 / 349 patched were checked; the rest were
inconclusive or unsupported.

**Agreement with recorded ground truth, not unseen-attack accuracy.** The 4,014 sandbox runs repeat controlled
recipes; 1,189 lack direct state measurements. Of the historical normals, 25,336 were checked, 4,984 inconclusive
and 69,778 unsupported. Zero findings does not mean every transaction was checked safe.
[Validation and limits](near/intents/reports/RESULTS.md)

## Coverage

**11-category taxonomy; served rules cover 3:** callback accounting, access-control abuse and resource exhaustion.
Categories describe patterns, not verified root causes.

| Covered evidence | Still needs protocol-specific checks |
|---|---|
| Failed callbacks and retained credit after refund | Token authenticity; async races / reentrancy |
| Direct private/admin calls | Signatures, replay and historical keys |
| Callback gas and log failures | Prices, arithmetic, shares, protocol balances and bridge proofs |

**Wallet drainers are not covered.** [Full taxonomy](near/intents/fixtures/attack_taxonomy.json). In that file,
"supported" for token spoofing means some direct receiver probes are visible; no served rule maps to it.

The served detector (rules + anomaly model) raised **0 high** and **84 Suspicious** alerts on 7,400 held-out normal
transactions; 80 came from one paused-contract hour. The anomaly model added no campaign detections. A retrained
model was **rejected** for false alarms; `intents_v1` and its rules are what is served.

## Quick start

Needs Python 3.12+ and [uv](https://docs.astral.sh/uv/); no Git LFS.

```bash
git clone -b near-security-oracle https://github.com/fuzious/security_oracle.git && cd security_oracle
unzip -o archives/near_intents.zip
uv sync

# Recorded evidence; no network or keys
uv run python -m near.demo.replay
# Expected: PASS: exploit high; normal low; account history 10/20 high.

uv run uvicorn near.service.app:app --port 8000
# Open http://localhost:8000/demo/
```

| Example input | Available evidence |
|---|---|
| October exploit | High-severity callback, log and retained-credit evidence |
| Normal deposit | No known pattern, with coverage shown |
| April callback attempt | Out-of-gas callback evidence; medium severity |
| Not flagged: rejected overdraw probe | A failed probe with no detected attack pattern |
| `intents.near` or exploiter account | Recent transactions; open a row to inspect evidence |

## Human review

Suspicious and high-severity transaction findings are automatically queued in the
[Human Oracle dashboard](http://localhost:8000/human/). Reviewers can inspect evidence, search and filter cases,
and confirm, dismiss or reopen findings with a saved note. The local demo requires no authentication;
review decisions do not execute on-chain actions. [Setup and behavior](near/human/README.md).

## Optional integrations

- **Rust source analysis:** inspect contract code alongside transaction evidence. Most real bugs are missed;
  this is a supporting signal. [Code-model evidence](near/model/reports/RESULTS.md)
- **On-chain response:** an operator can review evidence, publish an account verdict or confirm a report.
  The supplied router enforces that policy on future native NEAR payments routed through it. It cannot undo the
  inspected transaction, pause an arbitrary protocol, or turn a transaction label directly into an account block.
  [Contracts](near/contract/README.md) · [Response client](near/agent/README.md)

[Setup & API](near/README.md) · [License: BUSL-1.1](LICENSE)
