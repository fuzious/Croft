"""Collect benign-but-complex mainnet txs (hard negatives): flash-loan bots, liquidations, aggregator swaps.

These look structurally like exploits (flash loans, unverified bot contracts, many hops), so they test
precision. Sampled across 2021-2026 block windows; any tx in the exploit set is excluded.

    uv run python scripts/collect_hard_negatives.py --per-source 25  -> data/hard_negatives.jsonl
"""
import argparse
import json
import random
from pathlib import Path

from web3 import Web3

from oracle.sources import Etherscan

ROOT = Path(__file__).resolve().parents[1]
t = lambda sig: "0x" + Web3.keccak(text=sig).hex().removeprefix("0x")  # noqa: E731

LOG_SOURCES = {
    "balancer_flashloan": ("0xBA12222222228d8Ba445958a75a0704d566BF2C8",
                           t("FlashLoan(address,address,uint256,uint256)"), 12_300_000),
    "aave_v3_flashloan": ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
                          t("FlashLoan(address,address,address,uint256,uint8,uint256,uint16)"), 16_300_000),
    "aave_v3_liquidation": ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
                            t("LiquidationCall(address,address,address,uint256,uint256,address,bool)"), 16_300_000),
    "morpho_flashloan": ("0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb",
                         t("FlashLoan(address,address,uint256)"), 18_900_000),
}
TX_SOURCES = {
    "uniswap_universal_router": ("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", 17_200_000),
    "oneinch_v5_router": ("0x1111111254EEB25477B68fb85Ed929f73A960582", 15_600_000),
}
LATEST = 23_500_000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-source", type=int, default=25)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    es = Etherscan()
    exploit_txs = set()
    for f in ("exploits_all.jsonl",):
        for l in open(ROOT / "data" / f):
            exploit_txs.update(json.loads(l)["attack_txs"])

    out = []
    for name, (addr, topic, start) in LOG_SOURCES.items():
        picked = set()
        tries = 0
        while len(picked) < args.per_source and tries < 40:
            tries += 1
            b = rng.randrange(start, LATEST)
            body = es.call(module="logs", action="getLogs", address=addr, topic0=topic,
                           fromBlock=b, toBlock=b + 2000, page=1, offset=50)
            logs = body.get("result") if isinstance(body.get("result"), list) else []
            if logs:
                h = rng.choice(logs)["transactionHash"].lower()
                if h not in exploit_txs:
                    picked.add(h)
        out += [{"incident": f"hardneg:{name}:{h[:10]}", "source": name, "tx_hash": h, "label": 0} for h in picked]
        print(f"{name}: {len(picked)}", flush=True)

    for name, (addr, start) in TX_SOURCES.items():
        picked = set()
        tries = 0
        while len(picked) < args.per_source and tries < 40:
            tries += 1
            b = rng.randrange(start, LATEST)
            body = es.call(module="account", action="txlist", address=addr, startblock=b, endblock=b + 200,
                           page=1, offset=50, sort="asc")
            txs = [x for x in (body.get("result") if isinstance(body.get("result"), list) else [])
                   if x.get("isError") == "0"]
            if txs:
                h = rng.choice(txs)["hash"].lower()
                if h not in exploit_txs:
                    picked.add(h)
        out += [{"incident": f"hardneg:{name}:{h[:10]}", "source": name, "tx_hash": h, "label": 0} for h in picked]
        print(f"{name}: {len(picked)}", flush=True)

    (ROOT / "data" / "hard_negatives.jsonl").write_text("".join(json.dumps(o) + "\n" for o in out))
    print(f"done: {len(out)} hard negatives")


if __name__ == "__main__":
    main()
