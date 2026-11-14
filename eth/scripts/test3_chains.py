"""Runtime chain config for sealed test set v3 (polygon / arbitrum / optimism).

Mutates oracle.sources config dicts in-process only; nothing under oracle/ is modified on disk.
Import this module BEFORE constructing any Alchemy/Etherscan/Prices/CardBuilder for these chains.
"""
import json
from pathlib import Path

from oracle import sources

ROOT = Path(__file__).resolve().parents[1]

NEW_CHAINS = {
    "polygon": {"alchemy": "polygon-mainnet", "chainid": 137, "llama": "polygon", "native": "coingecko:matic-network",
                "native_symbol": "POL", "wrapped": "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"},
    "arbitrum": {"alchemy": "arb-mainnet", "chainid": 42161, "llama": "arbitrum", "native": "coingecko:ethereum",
                 "native_symbol": "ETH", "wrapped": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1"},
    "optimism": {"alchemy": "opt-mainnet", "chainid": 10, "llama": "optimism", "native": "coingecko:ethereum",
                 "native_symbol": "ETH", "wrapped": "0x4200000000000000000000000000000000000006"},
}
# fallback only (DefiLlama gap): native USDC / bridged USDC / USDT / DAI per chain
STABLES = {
    "polygon": {"0x2791bca1f2de4661ed88a30c99a7a9449aa84174", "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
                "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"},
    "arbitrum": {"0xff970a61a04b1ca14834a43f5de4533ebddb5cc8", "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
                 "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"},
    "optimism": {"0x7f5c764cbc14f9669b88837ca1490cca17c31607", "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
                 "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58", "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"},
}
DRPC_NET = {"polygon": "polygon", "arbitrum": "arbitrum", "optimism": "optimism"}
EXPLORER = {"polygon": r"polygonscan\.com", "arbitrum": r"arbiscan\.io", "optimism": r"optimistic\.etherscan\.io"}
FORK = {"polygon": "polygon", "arbitrum": "arbitrum", "optimism": "optimism"}


def install():
    sources.CHAINS.update(NEW_CHAINS)
    for c, s in STABLES.items():
        sources.Prices.STABLES[c] = s
        sources.Prices.ALCHEMY_NET[c] = NEW_CHAINS[c]["alchemy"]
        sources.Prices.NATIVE_SYMBOL[c] = NEW_CHAINS[c]["native_symbol"]
    sources.Drpc.KEYS.setdefault("polygon", "polygon")


def drpc_url(chain: str) -> str:
    """Keyed dRPC URL: rpc.json entry if present, else the same account key on that network's path."""
    cfg = json.loads((ROOT / "rpc.json").read_text())
    if chain in cfg and str(cfg[chain]).startswith("http"):
        return cfg[chain]
    base = cfg["polygon"]
    return base.replace("/polygon/", f"/{DRPC_NET[chain]}/")


class Drpc3(sources.Alchemy):
    def __init__(self, chain: str):
        self.chain = chain
        self.url = drpc_url(chain)
        self.namespace = f"drpc_{chain}"
        self.limit = sources.RateLimiter(8)


install()
