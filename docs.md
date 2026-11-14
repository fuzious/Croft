# Croft documentation

Croft analyzes NEAR Intents transactions and provides optional controls for future NEAR payments.
The Ethereum/EVM research code lives in `eth/`, with its own models, datasets and Python environment.

## Models

| Component | Role | Implementation |
| --- | --- | --- |
| **Jev / TypeSafe** | Research reference for typed decision models. The application does not call Jev. | [Jev and Laya](#jev-and-laya) |
| **Laya** | Implemented local inference, fine-tuning and evaluation experiments on Ethereum transaction fact cards; not the served NEAR transaction detector | [eval_laya.py](eth/scripts/eval_laya.py), [laya_smoke.py](eth/scripts/laya_smoke.py) |
| **Ethereum frozen v12** | Numeric histogram gradient boosting classifier over transaction features; separate from Laya | [freeze_v9.py](eth/scripts/freeze_v9.py), [results](eth/runs/RESULTS.md) |
| **Ethereum second stage** | Optional GPT-6-Astra review of flagged fact cards through the Codex CLI; separate from Laya and the NEAR service | [stage2.py](eth/scripts/stage2.py) |
| **NEAR Intents v1** | Served transaction detector: an Isolation Forest plus receipt rules, with accounting/history evidence added by the service | [model.py](near/intents/model.py), [service adapter](near/service/intents.py) |
| **NEAR source models** | Optional Rust-code risk models: classical v1 or a v2 classical/Qwen ensemble; missing or invalid artifacts fall back to rules | [predict.py](near/model/predict.py), [code_risk](near/service/app.py) |

### Jev and Laya

**Jev** is TypeSafe's System One model: an application supplies state and predefined questions, and receives
typed decisions and probability estimates instead of a generated explanation. TypeSafe describes its training
method as Reinforcement Learning for Calibrated Decisions (RLCD).
[TypeSafe's introduction](https://typesafe.ai/blog/introducing-system-one-models-and-jev).

**Laya** is a separate open-weight decision-model family published by Convai Innovations. Its model card
describes a non-autoregressive encoder with typed decision heads: it evaluates the input in a forward pass
rather than generating an answer token by token. The `typed-decisions` checkpoint used here is described as
ModernBERT-large, about 421M parameters. [Laya model card](https://huggingface.co/convaiinnovations/laya).
The [upstream implementation](https://github.com/NandhaKishorM/laya) documents its decision API and training.

Laya uses a Jev-style decision interface, with separate weights and implementation. Croft loads Laya from
Hugging Face for its Ethereum experiments. Probability calibration on transaction data must be measured separately.

Earlier Jev research notes are available through `git show f567294:docs/JEV_STUDY.md`.
Their API, version and pricing details describe that earlier research. Ethereum module docstrings still reference those notes.

### Laya experiments

The Ethereum environment declares `laya` in [eth/pyproject.toml](eth/pyproject.toml); [eth/uv.lock](eth/uv.lock)
pins the package to `0.4.7`. [eval_laya.py](eth/scripts/eval_laya.py) loads `convaiinnovations/laya`, subfolder
`typed-decisions`, and asks a `choice` question with `normal` and `exploit` options:

```python
agent = laya.load(BASE, subfolder=SUBFOLDER, device="mps")
answer = agent.system_one(card, QUESTIONS)["answers"]["verdict"]
p_exploit = float(answer["probabilities"]["exploit"])
```

The input is a decoded **fact card**, built by [card.py](eth/oracle/card.py): token transfers, priced value flows,
participants and execution mechanics. Arithmetic and feature extraction happen in Python before model scoring.
The script supports zero-shot evaluation, incident-grouped cross-validation and domain fine-tuning; `--save-final`
saves a persistent checkpoint. [eval_stack.py](eth/scripts/eval_stack.py) separately experiments with combining
Laya probabilities and numeric features. These are research entry points, not a production HTTP service.
`eval_laya.py` hardcodes Apple Metal (`mps`) for loading/fine-tuning; CPU or CUDA use requires adapting that script.

The frozen v12 scoring path instead loads a numeric estimator in [eval_test2.py](eth/scripts/eval_test2.py)
with `--tag v12`; the script's default tag is the older `v9`.
Its archived JSON metadata identifies **49 features**, histogram gradient boosting with depth 3 / 300 iterations,
and threshold **0.0625932142968897**, fitted on 4,443 development rows including 351 exploits.
The optional second stage clears a flag only for `legit` with reported confidence at least `0.8`; that confidence
is not independently calibrated. Existing results include wrongly cleared exploits; see [the results log](eth/runs/RESULTS.md).

The historical README lists `models/laya_frozen_v7` in the base model archive. Check its configuration and metadata
after extraction. Laya downloads do not pin a Hugging Face `revision`; record the downloaded revision and weight
hashes when reproducing experiments. The Python lockfile pins the package version only.

## NEAR service

1. **Entry points:** [near/service/app.py](near/service/app.py) exposes transaction scoring, account scans, source analysis,
   reviews, account-policy checks and signed approvals. Transaction scoring and account policy are different outputs.
2. **Transaction evidence:** [near/service/intents.py](near/service/intents.py) fetches FastNEAR receipts and calls the
   frozen `intents_v1` scorer. [features.py](near/intents/features.py) extracts features and receipt-rule hits;
   [accounting.py](near/intents/accounting.py) reconciles deposit/refund/credit events;
   [history.py](near/intents/history.py) links bounded earlier activity.
3. **Served model:** the bundled `near/models/intents_v1.json` manifest selects `iforest_global`, fitted on 69,863
   training normals. The implementation uses 300 trees, at most 2,048 samples per tree and seed 0. The loader checks
   artifact, feature-code and training-ID hashes. No Jev, Laya or generative LLM is used for this transaction score.
4. **Interpretation:** the response separates baseline model output, observed evidence, coverage and assessment.
   `risk` combines rule weights/anomaly percentiles; it is **not an attack probability**. Missing receipts and
   unsupported transactions have separate statuses from completed checks with no known pattern.
5. **Optional source analysis:** [near/model/predict.py](near/model/predict.py) honors `NEAR_ORACLE_MODEL`; otherwise it
   selects v2 only when its checkpoint and `torch`/`transformers` are available, else v1. V1 uses histogram gradient
   boosting over code features; v2 combines a classical model with a fine-tuned Qwen2.5-Coder-0.5B classifier, not Laya.
   See [llm_classifier.py](near/model/llm_classifier.py) and [freeze_v2.py](near/model/freeze_v2.py).
   If source-model loading/scoring fails, the API exposes `detectors-only` and `fallback_reason`.
   A missing or invalid **transaction** model instead returns HTTP 503; it does not use that source-analysis fallback.

The source-code model and transaction model have different labels, datasets and evaluation results. Rejected research
candidates remain under `near/model/` and `near/intents/`; the service continues to load the frozen models described above.
The README's minimal setup unpacks only the transaction archive; it does not enable the optional source classifiers.

## Repository layout

| Path | Contents |
| --- | --- |
| [near/service/](near/service/) | API, network adapters, source fetching, policy, reports, review storage and signing |
| [near/intents/](near/intents/) | Transaction features, rules, anomaly model, accounting, history and research |
| [near/analyzer/](near/analyzer/), [near/model/](near/model/) | Rust parsing/detectors and optional source-code classifiers |
| [near/contract/](near/contract/), [near/agent/](near/agent/) | Oracle/router Rust contracts, JS attester relay and payment wrapper |
| [near/demo/](near/demo/), [near/human/](near/human/) | Transaction inspector, offline replay and human review UI |
| [eth/oracle/](eth/oracle/), [eth/scripts/](eth/scripts/) | EVM trace/fork clients, fact cards, data collection, model training/evaluation and Laya experiments |
| [eth/contracts/](eth/contracts/) | Solidity OracleGate, demo contracts, Foundry tests and vendored libraries |
| [eth/runs/RESULTS.md](eth/runs/RESULTS.md) | Original Ethereum measurements, experiment history and known failure modes |
| [archives/](archives/) | NEAR artifact archives; extract from the repository root |
| [eth/archives/](eth/archives/) | Four original EVM dataset/model archives; extract from `eth/`, base archives before v12 overlays |

The repository root Python project installs **NEAR**. `eth/` has its own manifest, lockfile and `.venv` for
**Ethereum**, including Laya/Web3 dependencies. Run NEAR commands from the repository root and Ethereum commands from `eth/`.
`AGENTS.md` and `CLAUDE.md` are symlinks to `README.md`.

### Data and model artifacts

- `archives/near_intents.zip` is a regular Git object, sufficient for the transaction demo. It supplies `intents_v1`
  artifacts beneath `near/models/`. The JSON manifest and API response identify the loaded model.
- `archives/near_models.zip` and `archives/near_datasets.zip` use Git LFS for source-model artifacts/research data.
  Optional `archives/near_llm_v2.zip` is **not tracked**; without its weights the v2 source model is unavailable.
- `archives/near_transaction_research.zip` contains research outputs, including a rejected candidate, not a served upgrade.
- `eth/archives/{datasets,models}.zip` are bases; `{datasets,models}_v12.zip` are overlays. All four use Git LFS
  and total about 1.83 GB. Extracting only an overlay is not a complete environment.
- Some original NEAR research inputs and the EVM RPC cache are not bundled. A fresh clone can run the demo,
  but cannot reproduce every historical measurement without those inputs. See the per-chain setup guides.

For Ethereum, [freeze_v9.py](eth/scripts/freeze_v9.py) hashes `card.py`, `category.py` and `sources.py` together;
changing them invalidates comparisons with the frozen feature builder. NEAR loaders also verify source/artifact hashes.
Reproducing a result requires the matching commit, lockfile, model artifact and configuration.
Model loading uses Python pickle; only load trusted artifacts, even when their hashes match a supplied manifest.

## Policy and payment controls

| Component | Behavior |
| --- | --- |
| Findings → human decisions | [reviews.py](near/service/reviews.py) stores local annotations. Confirming a review does not update a blocklist or send an on-chain transaction. The demo review API has no authentication. |
| Account checks → policy | [policy.py](near/service/policy.py) combines signals into `allow/warn/block`. A high Intents transaction only warns; model-only high source risk warns unless an agreeing high-severity rule permits a block. Unavailable signals warn. |
| Reports → local blocks | [app.py](near/service/app.py) and [blocklist.py](near/service/blocklist.py): pending reports and confirmed local blocks are distinct; report confirmation requires `ORACLE_ADMIN_TOKEN`. These are separate from on-chain reports. |
| Approval API → signed payment | [preapprovals.py](near/service/preapprovals.py) requires explicit operator authorization. Signatures bind the recipient, amount, router, agent, key generation, expiry and nonce. Both [Rust contracts](near/contract/) enforce payment authorization. Use separate signing keys per network. |
| Payment client → funds | [wrapper.js](near/agent/src/wrapper.js) uses a scoped payment key. The [guarded router](near/contract/guarded_router/src/lib.rs) reserves funds before async calls, restores reservations after failed payments, enforces spending limits and consumes approval nonces. Its controls apply to future native NEAR payments routed through it. |
| External evidence → scoring | [source.py](near/service/source.py) and [intents.py](near/service/intents.py) bound responses and request times, validate source URLs and check receipt completeness. Receiver-published source is not proven to match deployed WASM; events are not independent balance proofs. |

Live NEAR reads use FastNEAR and, for account/source checks, configured RPC/indexer/source hosts. EVM collection
uses configured RPC, explorer and price services in [sources.py](eth/oracle/sources.py). Laya experiments download
weights from Hugging Face and then infer locally. The separate EVM `stage2.py` invokes hosted inference through
the Codex CLI, which sends the supplied fact card to the model provider.

## Results

Results are recorded separately for [NEAR transactions](near/intents/reports/RESULTS.md),
[accounting validation](near/intents/reports/accounting_validation.json), [source models](near/model/reports/RESULTS.md)
and [Ethereum](eth/runs/RESULTS.md). Reports distinguish controlled sandbox variants, repeated known attacks and
held-out cases. Unsupported rows have no completed accounting check. Source-model recall is limited;
Ethereum evaluations use historical traces rather than live pending transactions.

## Setup and tests

From a fresh checkout:

```bash
# Repository root: record the version and restore the bundled transaction model.
git rev-parse HEAD
unzip -o archives/near_intents.zip
uv sync --locked
uv run python -m near.demo.replay
uv run python -m unittest discover -s near -t . -p 'test_*.py'
(cd near/agent && npm ci && npm test)
(cd eth/contracts && forge test)
```

The replay uses recorded evidence; live UI lookups make network requests. Dependency installation can download packages.
Some tests skip without optional weights/datasets or the opt-in sandbox.
See [near/README.md](near/README.md) for Rust sandbox/API-to-contract tests and [eth/README.md](eth/README.md) for EVM setup.

Training, freeze and sealed-scoring scripts write model artifacts and reports. Use separate output paths for new
experiments and preserve the original `.started` markers, reports and manifests. Ethereum's `eval_test2.py`
documents a “score once” convention but does not prevent overwriting an earlier report.
