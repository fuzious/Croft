"""Collect a fresh, real-world mix of benign Ethereum txs for the sealed test set (never used in training).

Each source is an on-chain event (optionally from one contract); random block windows across 2021-2026
give one tx per window, so samples spread over time. Any tx seen in training is excluded.

    uv run python scripts/collect_testset.py  -> data/testset_normals.jsonl (traced via dRPC)
"""
import json
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from web3 import Web3

import build_dataset as bd

ROOT = Path(__file__).resolve().parents[1]
ev = lambda sig: "0x" + Web3.keccak(text=sig).hex().removeprefix("0x")  # noqa: E731
LATEST = 23_500_000
EXTRA_SOURCES = {  # added for test v2: everyday lending/DEX/NFT/staking flows
    "aave_v3_supply": ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "Supply(address,address,address,uint256,uint16)", 16_300_000, 40, 500, None),
    "aave_v3_withdraw": ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "Withdraw(address,address,address,uint256)", 16_300_000, 40, 500, None),
    "aave_v3_borrow": ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "Borrow(address,address,address,uint256,uint8,uint256,uint16)", 16_300_000, 40, 500, None),
    "compound_v3_withdraw": ("0xc3d688B66703497DAA19211EEdff47f25384cdc3", "Withdraw(address,address,uint256)", 15_400_000, 30, 2000, None),
    "uniswap_v3_swaps": (None, "Swap(address,address,int256,int256,uint160,uint128,int24)", 12_400_000, 60, 3, None),
    "seaport_fills": ("0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC", "OrderFulfilled(bytes32,address,address,address,(uint8,address,uint256,uint256)[],(uint8,address,uint256,uint256,address)[])", 16_500_000, 30, 300, None),
    "lido_withdraw_claims": ("0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1", "WithdrawalClaimed(uint256,address,address,uint256)", 17_200_000, 25, 3000, None),
    "eigenlayer_deposits": ("0x858646372CC42E1A627fcE94aa7A7033e7CF075A", "Deposit(address,address,address,uint256)", 17_400_000, 25, 3000, None),
    "erc4626_withdraw_sdai": ("0x83F20F44975D03b1b09e64809B757c47f942BEeA", "Withdraw(address,address,address,uint256,uint256)", 16_500_000, 25, 2000, None),
}

# name: (contract or None for any emitter, event signature, start block, target count, window, filter)
SOURCES = {
    # genuine flash loans
    "fl_balancer": ("0xBA12222222228d8Ba445958a75a0704d566BF2C8", "FlashLoan(address,address,uint256,uint256)", 12_300_000, 50, 3000, None),
    "fl_aave_v3": ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "FlashLoan(address,address,address,uint256,uint8,uint256,uint16)", 16_300_000, 50, 3000, None),
    "fl_aave_v2": ("0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", "FlashLoan(address,address,address,uint256,uint256,uint16)", 11_400_000, 30, 5000, None),
    "fl_morpho": ("0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb", "FlashLoan(address,address,uint256)", 18_900_000, 30, 3000, None),
    "fl_uniswap_v3": (None, "Flash(address,address,uint256,uint256,uint256,uint256)", 12_400_000, 40, 300, None),
    "fl_maker": ("0x60744434d6339a6B27d73d9Eda62b6F66a0a04FA", "FlashLoan(address,address,uint256,uint256)", 13_000_000, 15, 20000, None),
    # liquidations
    "liq_aave_v3": ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "LiquidationCall(address,address,address,uint256,uint256,address,bool)", 16_300_000, 40, 5000, None),
    "liq_aave_v2": ("0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", "LiquidationCall(address,address,address,uint256,uint256,address,bool)", 11_400_000, 30, 5000, None),
    "liq_compound": (None, "LiquidateBorrow(address,address,uint256,address,uint256)", 11_000_000, 30, 3000, None),
    "liq_morpho": ("0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb", "Liquidate(bytes32,address,address,uint256,uint256,uint256,uint256,uint256)", 18_900_000, 20, 10000, None),
    # aggregators / multi-protocol routes (tx.to = router)
    "agg_1inch_v5": ("0x1111111254EEB25477B68fb85Ed929f73A960582", None, 15_600_000, 35, 200, "to"),
    "agg_1inch_v6": ("0x111111125421cA6dc452d289314280a0f8842A65", None, 19_400_000, 35, 200, "to"),
    "agg_0x": ("0xDef1C0ded9bec7F1a1670819833240f027b25EfF", None, 11_600_000, 35, 200, "to"),
    "agg_cow": ("0x9008D19f58AAbD9eD0D60971565AA8510560ab41", "Settlement(address)", 12_600_000, 35, 500, None),
    "agg_paraswap": ("0xDEF171Fe48CF0115B1d80b88dc8eAB4f0B1a3f00", None, 12_300_000, 25, 300, "to"),
    "agg_universal_router": ("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", None, 17_200_000, 35, 100, "to"),
    # vaults / staking / LP
    "lido_submit": ("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", "Submitted(address,uint256,address)", 11_500_000, 30, 1000, None),
    "curve_3pool": ("0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7", None, 11_000_000, 30, 500, "to"),
    "convex_booster": ("0xF403C135812408BFbE8713b5A23a04b3D48AAE31", "Deposited(address,uint256,uint256)", 12_500_000, 25, 1000, None),
    "erc4626_sdai": ("0x83F20F44975D03b1b09e64809B757c47f942BEeA", "Deposit(address,address,uint256,uint256)", 16_500_000, 25, 2000, None),
    "pendle_router": ("0x888888888889758F76e7103c6CbF23ABbF58F946", None, 18_000_000, 25, 500, "to"),
    "uniswap_v3_lp": ("0xC36442b4a4522E871399CD717aBDD847Ab11FE88", None, 12_400_000, 25, 200, "to"),
    # bridges
    "bridge_across": ("0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5", None, 17_000_000, 25, 500, "to"),
    "bridge_stargate": ("0x8731d54E9D02c286767d56ac03e8037C07e01e98", None, 14_400_000, 25, 1000, "to"),
    "bridge_arbitrum": ("0x72Ce9c846789fdB6fC1f34aC4AD25Dd9ef7031ef", None, 13_000_000, 20, 1000, "to"),
    # treasuries / governance
    "safe_exec": (None, "ExecutionSuccess(bytes32,uint256)", 12_000_000, 60, 100, None),
    "timelock_exec": (None, "ExecuteTransaction(bytes32,address,uint256,string,bytes,uint256)", 11_000_000, 25, 20000, None),
    # MEV / searchers (unverified bots trading on Uniswap V2 pairs)
    "mev_bots": (None, "Swap(address,uint256,uint256,uint256,uint256,address)", 11_000_000, 60, 5, "unverified_to"),
}


def main():
    import argparse
    global LATEST
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="testset_normals.jsonl")
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--latest", type=int, default=LATEST)
    ap.add_argument("--extra", action="store_true", help="include EXTRA_SOURCES")
    ap.add_argument("--exclude", nargs="*", default=[], help="more jsonl files whose tx_hash must be excluded")
    args = ap.parse_args()
    LATEST = args.latest
    if args.extra:
        SOURCES.update(EXTRA_SOURCES)
    rng = random.Random(args.seed)
    seen = set(json.loads((ROOT / "models" / "train_tx_hashes.json").read_text()))
    for f in (list((ROOT / "data").glob("dataset*.jsonl")) + [ROOT / "data" / "exploits_all.jsonl"]
              + [ROOT / "data" / x for x in args.exclude]):
        for l in open(f):
            r = json.loads(l)
            seen.update([r.get("tx_hash")] + r.get("attack_txs", []))
    out_path = ROOT / "data" / args.out
    done = {json.loads(l)["tx_hash"] for l in open(out_path)} if out_path.exists() else set()
    lock = threading.Lock()

    def sample(name):
        addr, sig, start, target, window, flt = SOURCES[name]
        target = max(1, int(target * args.scale))
        got, tries = 0, 0
        while got < target and tries < target * 6:
            tries += 1
            b = rng.randrange(start, LATEST - window)
            if flt in ("to",):
                block = bd.alchemy.rpc("eth_getBlockByNumber", [hex(b), True], cache=False)
                cands = [t for t in block.get("transactions", []) if (t.get("to") or "").lower() == addr.lower()]
                if not cands:  # sparse router: walk a few blocks
                    continue
                h, protected = rng.choice(cands)["hash"].lower(), addr.lower()
            else:
                params = {"module": "logs", "action": "getLogs", "topic0": ev(sig), "fromBlock": b,
                          "toBlock": b + window, "page": 1, "offset": 100}
                if addr:
                    params["address"] = addr
                try:
                    body = bd.etherscan.call(**params)
                except RuntimeError:  # explorer throttled: skip this window
                    continue
                logs = body.get("result") if isinstance(body.get("result"), list) else []
                if not logs:
                    continue
                lg = rng.choice(logs)
                h, protected = lg["transactionHash"].lower(), lg["address"].lower()
                if flt == "unverified_to":
                    tx = bd.alchemy.tx(h)
                    if not tx.get("to") or bd.etherscan.source(tx["to"])["verified"]:
                        continue
            if h in seen or h in done:
                continue
            try:
                if not bd.etherscan.source(protected)["verified"]:
                    continue
                rec = bd.replay_and_store(h)
            except (RuntimeError, LookupError):
                continue
            if not (rec and rec["ok"] and rec.get("source") == "mainnet_trace"):
                continue
            with lock:
                if h in done:
                    continue
                done.add(h)
                with out_path.open("a") as fh:
                    fh.write(json.dumps({"incident": f"{args.out.split('_')[0]}:{name}:{h[:10]}", "source": name, "tx_hash": h,
                                         "label": 0, "chain": "eth", "block": int(rec["tx"]["blockNumber"], 16),
                                         "victim": protected, "month": None}) + "\n")
            got += 1
        print(f"{name}: {got}/{target}", flush=True)

    with ThreadPoolExecutor(3) as pool:
        list(pool.map(sample, SOURCES))
    print(f"done: {len(done)} test normals -> {out_path}")


if __name__ == "__main__":
    main()
