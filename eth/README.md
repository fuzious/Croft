# Croft · Ethereum / EVM

The Ethereum project from `main` is preserved here: `oracle/` builds transaction fact
cards, `scripts/` collects and evaluates data, and `contracts/` contains the Solidity
gate and its dependencies. Paths, source code, dependency lockfile and archived data
retain their original layout beneath `eth/`.

## Setup

Requires Python 3.12–3.14, uv, Git LFS, and Foundry for contract tests or fork replay.
Run these commands from the repository root:

```bash
git lfs pull --include="eth/archives/*.zip"
cd eth
uv sync --locked
unzip -o archives/datasets.zip
unzip -o archives/models.zip
unzip -o archives/datasets_v12.zip
unzip -o archives/models_v12.zip
```

The v12 archives are overlays: extract them **after** the base archives, always from
`eth/`. All four original archives are retained unchanged (about 1.83 GB total).
They restore `eth/data/` and `eth/models/`; extracted files remain gitignored.
The original RPC cache was not bundled and is rebuilt on demand.

Put API keys in `eth/.env` (`ALCHEMY_KEY`, `ETHERSCAN_API_KEY`) and RPC settings in
`eth/rpc.json`; both are gitignored. Live collection requires configured RPC access.

## Run

From `eth/`:

```bash
uv run python scripts/build_dataset.py
uv run python scripts/make_cards.py --version v10
uv run python scripts/verify_labels.py --cards data/cards_v10.jsonl
uv run python scripts/eval_nested.py --cards data/cards_v10_clean.jsonl
(cd contracts && forge test)
```

Training, freeze, holdout and stage-two scripts are retained for reproducing the
original experiments. Sealed test sets are scored once; do not reuse them as fresh
holdouts. Frozen-model checks depend on the unchanged feature-builder source files.
The original [results log](runs/RESULTS.md) preserves measurements and limitations.
Results use historical traces; the Solidity gate is a proof of concept.

[License](LICENSE).
