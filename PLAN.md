# Security Oracle: plan

**Goal:** decide before execution whether an Ethereum transaction is safe to allow, cheaply enough to check every transaction we care about and fast enough to sit inline. The model layer is **TypeSafe Jev (primary, chosen for speed and cost)** behind a vendor-neutral interface. OpenAI's Decisions API is the backup and the long-context experiment; Luna/Sol through Responses are the escalation and explanation tier.

**Priorities (from the user): speed and cost first. Privacy / data retention is not a constraint.**

**North-star result:** publish the first credible, reproducible number for "Jev-based firewall catches X% of real exploits at Y false-positive rate", on a time-split benchmark we release ourselves. No such result exists today; the viral "94%" was a confidence score on one made-up example (see `docs/JEV_STUDY.md` §4).

---

## 1. Core insight

Jev reads English and JSON state and returns calibrated probabilities. It can't read EVM hex, it's weak at arithmetic, and it has about 32k tokens for state. **Most of the moat is the layer that turns a raw transaction into a compact, decoded, priced, labelled story**: who gained money, who lost it, how, and through which contracts. Jev then answers about 15 sharp questions about that story in one call, for about $0.0005 and about 300 ms. A small trained classifier turns those answers into a verdict.

## 1b. Model strategy: start with Jev, finish with our own local model

Speed and cost are the priorities, so the endgame is a **fine-tuned local decision model on the hot path**. Open-source Jev clones exist (JEV_STUDY §6c):

| Stage | Hot-path model | Why |
|---|---|---|
| Phase 0–1 (no labels yet) | **Jev API** (zero-shot) | Best out-of-the-box judgment. Nothing to train yet |
| Phase 2 bake-off | Jev vs **Von/Laya (395–421M encoder, fine-tuned)** vs **Kev-4B/9B (LoRA)** vs `so1` + Qwen 27B zero-shot | Same question panel; Von and Kev speak Jev's `/v1/systemone` API, so swapping is a base-URL change |
| Production (expected) | **Fine-tuned ~400M encoder on our own GPU**: ~25 ms, close to $0 per transaction | One benchmark showed fine-tuned Laya beating Jev (76.9% vs 72.7%) at 23 ms. Inference fits the ≤4k-token state inside an 8k window |
| Gray zone | Jev (second opinion) → Luna/Sol (explanation) → human | Keep the strong general models only for the few percent of uncertain transactions |

Fine-tuning data: our labelled exploits + hard negatives (§4), **plus Jev/Sol answers on unlabelled benign traffic as soft labels** (distillation). Exploit labels always come from real incidents, never from model output.

## 2. Architecture

```
                ┌────────────────────────── Security Oracle ──────────────────────────┐
 tx / userOp /  │ L0 Rules        sanctioned/known-exploiter addrs, blocklists, trivial allow   │  <1 ms
 Safe proposal ─┤ L1 Simulate     fork at head (revm/anvil, own reth node) → call trace,        │  20–150 ms
 / deployment   │                 storage diffs, logs, balance deltas                            │
                │ L2 Compile      decode (Sourcify/Etherscan ABIs), label (protocol registry),   │  10–50 ms
                │   "state"       price (USD), compute economics (net P&L per actor), flags,      │
                │                 strip attacker-controlled strings → ≤8–20k tokens              │
                │ L3 Decision     1 call: ~15 Noul/predicate signals + Score(severity) +         │  70–500 ms
                │   panel         Choice(verdict); backend = Jev | OpenAI Decisions | both       │
                │ L4 Meta-model   GBDT/logistic on [Jev probs + numeric features], isotonic-      │  <1 ms
                │                 calibrated; thresholds per target FPR → allow/warn/review/block │
                │ L5 Escalate     gray zone → Luna (full trace, explanation) → human queue       │  async
                └──────────────────────── logs: state hash, model ver, probs, verdict ─────────┘
```

### Draft Jev question panel (the L3 call)
Noul signals (p(true)):
- The transaction sender is a net USD winner, and the losers are protocol-owned contracts or pools, not counterparties in a trade.
- A flash loan funds the transaction, and an oracle or pool price that the protocol reads moves sharply within the same transaction.
- The transaction calls a privileged or admin function (upgrade, setOwner, setImplementation, mint, withdrawAll) from an address that isn't the documented admin.
- The transaction runs code in the context of a wallet or proxy (delegatecall) on a recently deployed or unverified contract.
- The same function is entered again before its first call finishes (reentrancy).
- Collateral or share accounting doesn't match the assets that moved (e.g. shares minted with no matching deposit).
- The transaction grants unlimited token allowance or a Permit/Permit2 signature to a fresh or unverified address.
- Value moves straight on to a mixer, a bridge or freshly created addresses.
- The pattern resembles a known exploit class: price manipulation, access control, reentrancy, rounding/precision, signature replay, or an uninitialized proxy.
- The pattern is better explained as ordinary MEV (arbitrage, liquidation, backrun) or as treasury or governance housekeeping.

Plus `Score severity(0–4)` and `Choice verdict{allow, warn, review, block}`.
**Use the Noul/predicate probabilities as the main features.** Community tests show choice-question probabilities are overconfident and change with option order (JEV_STUDY §6b). The meta-model makes the final call anyway.
The MEV question in the list exists on purpose: arbitrage and liquidations are the **main source of false positives**.

## 3. Products (three tracks over one engine)

| Track | What | Who buys | Latency budget | Why it matters |
|---|---|---|---|---|
| **A. Treasury / multisig guard** | Safe Guard module plus a watcher on the Safe transaction service: every proposed transaction is simulated and scored *before signers sign* | DAOs, funds, exchanges, protocol treasuries | Seconds to minutes (relaxed) | Bybit (Feb 2025, ~$1.5B): signers approved a transaction that swapped the Safe's implementation through delegatecall. Pre-signing simulation plus a "privileged call to unverified code" signal targets exactly that |
| **B. Protocol firewall ("oracle")** | Sensitive protocol functions require an EIP-712 attestation from the oracle (or a hook in Uniswap v4, ERC-4626 vaults or an L2 sequencer), and the protocol gets a pause on high-severity signals | Lending, vaults, bridges | <500 ms | Stops exploits inline even when the attacker uses private orderflow |
| **C. Watchtower** | Scores **every new contract deployment** (decompiled summary) plus public-mempool transactions touching protocols we cover, and sends alerts or automated pause bundles | Security teams, insurers | ~1 block | Exploit contracts are often deployed before the attack, which gives an early warning. Note that mempool watching misses attacks sent privately |

**Recommended order: A → B → C.** A ships fastest because there's little volume and latency doesn't matter, it has a clear buyer and story, and Jev plus Luna can both run on every proposal. B is the main ambition. C reuses the engine and makes the published benchmark more credible.

## 4. Data

| Set | Source | Use |
|---|---|---|
| Positives: exploits | DeFiHackLabs (hundreds of Foundry PoCs with fork blocks), rekt.news, SlowMist Hacked, De.Fi REKT DB | Replay on forks → real traces |
| Positives: wallet drains | Forta labelled-datasets, ScamSniffer, Etherscan `phish-hack` labels | Wallet and Permit cases (tracks A/C) |
| Positives: exploit contracts | Contracts deployed by the attackers in the incidents above | Precursor classifier (track C) |
| **Hard negatives** | MEV arbitrage and liquidations (EigenPhi, libmev), flash-loan refinancing, large whale swaps, governance executions, admin upgrades by real admins | Teaches the difference between unusual and malicious; this is where models fail |
| Easy negatives | Stratified sample of mainnet transactions, same protocols and same weeks as the positives | Measuring false-positive rate at realistic base rates |
| Synthetic variants | A frontier model plus Foundry mutates PoCs: different amounts, new wrapper contracts, split steps, renamed functions | Robustness and anti-memorisation |
| Adversarial | Prompt-injection strings in token or contract names, attacks disguised as arbitrage | Red-team set |

**Split:** train on everything before cutoff T; **test on exploits after T** that the model hasn't seen (the newest ~20%).

## 5. Evaluation (the bake-off)

Systems compared on the same states:
1. **Baseline without an LLM:** XGBoost on numeric features only. Any model has to beat this to justify itself.
2. Jev with the `verdict` Choice only.
3. Jev with the full question panel, thresholded by hand.
4. **Jev panel + meta-model** (the expected winner).
5. **OpenAI Decisions API** panel (same questions, predicates) + meta-model.
6. **Ensemble:** Jev predicates + Decisions predicates → meta-model.
7. **Long-context variant:** Decisions API given the *full* decoded trace instead of the compressed state (if its context really is ~1M).
8. Luna through Responses, prompted to classify.
9. Sol or Fable, prompted (sets the upper bound on quality, but too expensive to run on everything).
10. Cascade: the best of 4–7 with the gray zone escalated to Luna.

Metrics: **recall at FPR 1e-3 and 1e-4**, PR-AUC, calibration (ECE/Brier), p50/p95 latency, $ per 1M transactions, and recall broken down by exploit class.

## 6. Cost and throughput (back of envelope)

- Ethereum mainnet is roughly 1–2M transactions/day. At about 8k tokens of state each: ~12B tokens/day × $0.042/M ≈ **$500/day to score every mainnet transaction with Jev**.
- Jev's default rate limit is 100K tok/s ≈ 8.6B tokens/day → **we need a pre-filter** (only contract interactions with real value flow) or an enterprise limit.
- **Simulation is the real bottleneck, not the model.** We need our own reth/erigon node with tracing plus revm-based parallel simulation. Hosted simulators cost too much at this scale.
- Track A at multisig volume is negligible: about a cent per proposal, even with Luna.

### Speed and cost levers (priority)
- **The model costs almost nothing per transaction:** an 8k-token state is ~$0.00034 with Jev. Halving state tokens halves the cost and reduces latency, so the compiler should aim for **≤4k tokens** on typical transactions and save the long form for escalation.
- **Most transactions should skip the model:** L0 rules allow plain ETH transfers, known-router swaps under a size threshold and verified-admin housekeeping without calling it. Target: ≥70% of traffic never reaches it.
- **One call per transaction**, all questions batched (12× cheaper and 10× faster than separate calls).
- **Two-stage overlap:** fire a cheap *static* Jev check on decoded calldata and target metadata **in parallel with simulation**, then a post-simulation check only if the static check or the economics look risky. This hides model latency behind simulation latency.
- **Simulation is the latency floor:** own reth node in the same region, revm in-process, warm state cache for hot protocols. Target p95 under 150 ms for simulate plus compile.
- **Region:** put the oracle next to TypeSafe's API (US West, according to their eval setup) and measure p95, which will be dominated by network time.
- **Budget target:** ≤ $0.0002 per screened transaction and ≤ 300 ms p95 end to end on the hot path. With a local fine-tuned encoder the model cost is ≈ $0 and model latency ~25 ms, so **simulation becomes the whole budget**.

## 7. Phases

| Phase | Weeks | Deliverables | Exit criterion |
|---|---|---|---|
| **0. Spike** | 1 | Jev and OpenAI keys, a tracing RPC, Python repo. Hand-build states for 10 famous exploits (Euler, Nomad, Curve/Vyper, Bybit, Cream, Beanstalk, …) and 20 hard negatives; run Jev. Answer the open questions in JEV_STUDY §8 | Jev clearly separates the 10 from the 20 on at least a few signals |
| **1. Data + compiler** | 2–4 | DeFiHackLabs replay harness, benign sampler, address/protocol labeller, USD pricer, trace → state compiler v1 with injection-safe string handling | ≥200 exploit and ≥20k benign states, all ≤20k tokens |
| **2. Bake-off** | 4–6 | §5 report, meta-model, calibration curves, per-class recall | Pick the architecture from the numbers |
| **3. Track A MVP** | 6–9 | Safe transaction-service watcher, Slack/Telegram alert with Luna's explanation, then a Safe Guard that requires the oracle's OK above a severity level | 3 pilot multisigs |
| **4. Red team** | 8–10 | Adversarial set, injection tests, attacks disguised as MEV; harden the compiler | Recall drop under attack is <10 points |
| **5. Publish** | 10–12 | Open benchmark ("EVM-Exploit-Bench") plus write-up with honest numbers | Public, reproducible result |
| **6. Track B** | 12+ | EIP-712 attestation guard contracts, latency-hardened hot path, pause automation | One protocol integration in shadow mode |

## 8. Repo layout (to scaffold)

```
security_oracle/
  PLAN.md  docs/JEV_STUDY.md
  oracle/
    rules/        # L0
    simulate/     # L1: fork + trace (anvil/revm, RPC client)
    compile/      # L2: decode, label, price, economics, sanitize → state
    decide/       # L3: question panel (vendor-neutral), backends/{jev,von_kev_local,openai_decisions}.py, logging
    train/        # fine-tune + calibrate local encoder (Laya/Von) and Kev LoRA; distillation from Jev/Sol
    meta/         # L4: features, training, calibration, thresholds
    escalate/     # L5: Luna explainer
  data/           # manifests only (raw traces gitignored)
  bench/          # bake-off runner + report
  integrations/   # safe_guard/, attestation/, watchtower/
```
Stack: Python (uv) for the pipeline and evals; Foundry for replays and contracts; a Rust/revm sidecar later if simulation becomes the bottleneck.

## 9. Risks

| Risk | Mitigation |
|---|---|
| Jev can't tell exploits from MEV | Hard negatives, the MEV question, and the meta-model weighting deterministic economics |
| Prompt injection through token or contract names | Sanitize in the compiler and use our own registry labels only; red-team set |
| Data leakage (PoCs memorised by the models) | Time split, synthetic variants, report results on post-cutoff exploits |
| Decision-model refusals on exploit content | Decisions API can return a `refusal` answer → treat it as a `review` and track the refusal rate in the bake-off |
| Vendor lock-in or price change | `DecisionBackend` interface; the production goal is our **own fine-tuned local model**, with Jev / OpenAI as fallbacks |
| OSS Jev clones are new and unproven (all <1 month old, self-reported numbers) | Pin commits, re-run every claim in our bake-off, and keep Jev as the fallback |
| Attackers using private orderflow | Tracks A and B are inline and don't depend on the mempool; track C uses deployment precursors |
| Early-access limits | Pre-filter, pin the version, apply for an enterprise tier early |

## 10. Decisions needed from you
1. Does the **A → B → C** order work for you, or should track B come first?
2. Jev key (possibly available through OpenRouter now)? An OpenAI key is optional, only for the backup and escalation tiers.
3. Node: run our own reth archive node, or start on a tracing RPC provider (Alchemy, QuickNode) for phases 0–2?
4. Open-source the benchmark (my recommendation), or keep it private?
