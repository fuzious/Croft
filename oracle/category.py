"""Protocol category of a (verified) victim contract, from its name and ABI. Used to put the protocol
type on the card and to report precision/recall per category (the guard can be category-specific)."""
from __future__ import annotations

import re

from .sources import Etherscan

RULES = [  # (category, name regex, ABI function names) -- first match wins
    ("bridge", r"bridge|portal|gateway|relay|messenger|wormhole|layerzero|router.?v?\d*bridge",
     {"bridge", "relayMessage", "finalizeWithdrawal", "processMessage", "receiveMessage", "lzReceive",
      "executeMessage", "claimMessage"}),
    ("lending", r"lend|loan|comptroller|ctoken|cerc20|cether|pool.?configurator|morpho|silo|market|cauldron|vat\b",
     {"borrow", "repayBorrow", "liquidateBorrow", "liquidationCall", "liquidate", "borrowBalanceCurrent",
      "addCollateral", "removeCollateral", "getAccountLiquidity"}),
    ("dex", r"swap|pair|amm|dex|exchange|curve|uniswap|sushi|balancer|router|pool",
     {"swap", "swapExactTokensForTokens", "addLiquidity", "removeLiquidity", "exchange", "getReserves",
      "add_liquidity", "remove_liquidity", "swapExactInput"}),
    ("vault/yield", r"vault|strategy|farm|staking|stake|yield|chef|reward|gauge|savings|treasury|bond",
     {"deposit", "withdraw", "harvest", "earn", "stake", "unstake", "getReward", "claimRewards",
      "redeem", "convertToAssets"}),
    ("token", r"token|coin|erc20|\$",
     {"transfer", "transferFrom", "approve"}),
]
HARDNEG_CATEGORY = {"balancer_flashloan": "dex", "aave_v3_flashloan": "lending", "aave_v3_liquidation": "lending",
                    "morpho_flashloan": "lending", "uniswap_universal_router": "dex", "oneinch_v5_router": "dex"}


def categorize(etherscan: Etherscan, address: str) -> str:
    src = etherscan.source(address)
    abi = src["abi"] or []
    if src["proxy"] and src["implementation"]:
        impl = etherscan.source(src["implementation"])
        abi = abi + (impl["abi"] or [])
        name = f"{src['name'] or ''} {impl['name'] or ''}"
    else:
        name = src["name"] or ""
    fns = {i.get("name") for i in abi if i.get("type") == "function"}
    for cat, rx, keys in RULES:
        if re.search(rx, name, re.I) or (cat != "token" and len(fns & keys) >= 2):
            return cat
    if {"transfer", "transferFrom", "approve"} <= fns:
        return "token"
    return "other"
