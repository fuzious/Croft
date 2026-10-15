"""Runtime chain config for sealed test set v4 (new DeFiHackLabs chains). Mutates oracle.sources dicts
in-process only (nothing under oracle/ is modified on disk). Import BEFORE constructing any clients.

Per chain: `rpc` = which client serves tx/receipt/block ("alchemy" key 1 or "drpc"), Etherscan v2 chainid
(None = explorer not on Etherscan v2), alternative etherscan-compatible explorer API (no key) if any.
"""
import json
from pathlib import Path

from oracle import sources

ROOT = Path(__file__).resolve().parents[1]

NEW_CHAINS = {
    "avalanche": {"alchemy": "avax-mainnet", "chainid": 43114, "llama": "avax", "native": "coingecko:avalanche-2",
                  "native_symbol": "AVAX", "wrapped": "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7"},
    "fantom": {"alchemy": "fantom-mainnet", "chainid": 250, "llama": "fantom", "native": "coingecko:fantom",
               "native_symbol": "FTM", "wrapped": "0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83"},
    "gnosis": {"alchemy": "gnosis-mainnet", "chainid": 100, "llama": "xdai", "native": "coingecko:xdai",
               "native_symbol": "XDAI", "wrapped": "0xe91d153e0b41518a2ce8dd3d7944fa863463a97d"},
    "linea": {"alchemy": "linea-mainnet", "chainid": 59144, "llama": "linea", "native": "coingecko:ethereum",
              "native_symbol": "ETH", "wrapped": "0xe5d7c2a44ffddf6b295a15c148167daaaf5cf34f"},
    "blast": {"alchemy": "blast-mainnet", "chainid": 81457, "llama": "blast", "native": "coingecko:ethereum",
              "native_symbol": "ETH", "wrapped": "0x4300000000000000000000000000000000000004"},
    "mantle": {"alchemy": "mantle-mainnet", "chainid": 5000, "llama": "mantle", "native": "coingecko:mantle",
               "native_symbol": "MNT", "wrapped": "0x78c1b0c915c4faa5fffa6cabf0219da63d7f4cb8"},
    "sei": {"alchemy": "sei-mainnet", "chainid": 1329, "llama": "sei", "native": "coingecko:sei-network",
            "native_symbol": "SEI", "wrapped": "0xe30fedd158a2e3b13e9badaeabafc5516e95e8c7"},
    "zksync": {"alchemy": "zksync-mainnet", "chainid": 324, "llama": "era", "native": "coingecko:ethereum",
               "native_symbol": "ETH", "wrapped": "0x5aea5775959fbc2557cc8789bc1bf90a239d9a91"},
    "moonriver": {"alchemy": "moonriver-mainnet", "chainid": 1285, "llama": "moonriver",
                  "native": "coingecko:moonriver", "native_symbol": "MOVR",
                  "wrapped": "0x98878b06940ae243284ca214f92bb71a2b032b8a"},
}
# which client serves eth_getTransactionByHash/receipt/blocks (Alchemy apps not enabled for some chains)
RPC = {"avalanche": "public", "fantom": "drpc", "gnosis": "public", "linea": "alchemy", "blast": "alchemy",
       "mantle": "alchemy", "sei": "drpc", "zksync": "alchemy", "moonriver": "drpc"}
DRPC_NET = {"avalanche": "avalanche", "fantom": "fantom", "gnosis": "gnosis", "linea": "linea", "blast": "blast",
            "mantle": "mantle", "sei": "sei", "zksync": "zksync", "moonriver": "moonriver",
            "eth": "ethereum", "bsc": "bsc", "base": "base"}
# keyless public endpoints where dRPC/Alchemy lack history: gnosis serves archive debug traces,
# avalanche serves historical txs (and is used as the anvil fork upstream)
PUBLIC = {"gnosis": "https://rpc.gnosischain.com", "avalanche": "https://api.avax.network/ext/bc/C/rpc"}
# which endpoint serves debug_traceTransaction (exact on-chain trace); other chains use anvil replay
TRACE = {"linea": "drpc", "gnosis": "public"}
ETHERSCAN_V2 = {"avalanche", "gnosis", "linea", "blast", "mantle", "sei"}  # getsourcecode works on free tier
FORK = {c: c for c in NEW_CHAINS}


def install():
    for c, cfg in NEW_CHAINS.items():
        sources.CHAINS.setdefault(c, cfg)


def drpc_url(chain: str) -> str:
    cfg = json.loads((ROOT / "rpc.json").read_text())
    return cfg["polygon"].replace("/polygon/", f"/{DRPC_NET[chain]}/")


class Drpc4(sources.Alchemy):
    def __init__(self, chain: str):
        self.chain = chain
        self.url = drpc_url(chain)
        self.namespace = f"drpc_{chain}"
        self.limit = sources.RateLimiter(8)


install()


class Public4(sources.Alchemy):
    def __init__(self, chain: str):
        self.chain = chain
        self.url = PUBLIC[chain]
        self.namespace = f"public_{chain}"
        self.limit = sources.RateLimiter(4)
