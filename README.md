# Croft

Transaction security research for Ethereum/EVM and NEAR.

Presentation video: <https://youtu.be/_q4_Ea43KwE>

| Project | Contents | Start here |
| --- | --- | --- |
| Ethereum / EVM | Fact cards, exploit datasets, frozen models, collection/evaluation scripts and Solidity gate | [eth/README.md](eth/README.md) |
| NEAR | Intents transaction analysis, review dashboard, Rust contracts and payment adapters | [near/README.md](near/README.md) |

The projects use separate Python environments. Run Ethereum commands from `eth/`;
run NEAR commands from the repository root. Ethereum data and models are preserved
in `eth/archives/` with their v12 overlays; NEAR archives remain in `archives/`.

Historical evaluation results are research evidence, not guarantees of live exploit prevention.
See [LICENSE](LICENSE) for usage terms.
