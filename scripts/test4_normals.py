"""Sealed test v4 normals (label 0) on Ethereum: everyday protocol flows sampled by event or tx target.

Each sub-family samples random block windows uniformly over [max(start, 2021-01), head] (one tx per window),
picks one matching log (or one tx sent to the target), checks the protocol-side contract is verified on
Etherscan, and stores the exact on-chain execution (dRPC callTracer + receipt logs) in data/replays/<hash>.json.
Every hash used anywhere in the project (data/*.jsonl|json, data/cards, models/*_tx_hashes.json) and every
pre-existing replay file is excluded.

    uv run python scripts/test4_normals.py --check          # verify addresses / event topics only
    uv run python scripts/test4_normals.py --workers 8      # -> data/test4_eth_families.jsonl (resumable)
"""
import argparse
import json
import math
import random
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from web3 import Web3

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test4_common as cm  # noqa: E402
from oracle.sources import Drpc  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "test4_eth_families.jsonl"
SEED = 90210
LO = 11_565_000  # ~2021-01-01
ev = lambda sig: "0x" + Web3.keccak(text=sig).hex().removeprefix("0x")  # noqa: E731

UNI2_FACTORY = "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f"
UNI3_FACTORY = "0x1f98431c8ad98523631ae4a59f267346ea31f984"
COMPTROLLER = "0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b"

E4626 = ["Deposit(address,address,uint256,uint256)", "Withdraw(address,address,address,uint256,uint256)"]
AAVE = ["Supply(address,address,address,uint256,uint16)", "Withdraw(address,address,address,uint256)",
        "Borrow(address,address,address,uint256,uint8,uint256,uint16)", "Repay(address,address,address,uint256,bool)"]
UNI2_SWAP = "Swap(address,uint256,uint256,uint256,uint256,address)"
UNI3_SWAP = "Swap(address,address,int256,int256,uint160,uint128,int24)"
AAVE_POOL = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"
SPARK_POOL = "0xC13e21B648A5Ee794902342038FF3aDAB66BE987"
COMETS = ["0xc3d688B66703497DAA19211EEdff47f25384cdc3", "0xA17581A9E3356d9A858b789D68B4d866e593aE94",
          "0x3Afdc9BCA9213A35503b077a6072F3D0d5AB0840"]
MORPHO = "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb"
BAL_VAULT = "0xBA12222222228d8Ba445958a75a0704d566BF2C8"
YEARN_V3 = ["0xBe53A109B494E5c9f97b9Cd39Fe969BE68BF6204", "0x028eC7330ff87667b6dfb0D94b954c820195336c",
            "0xc56413869c6CDf96496f2b1eF801fEDBdFA7dDB0", "0x182863131F9a4630fF9E27830d945B1413e347E8"]
METAMORPHO = ["0xBEEF01735c132Ada46AA9aA4c54623cAA92A64CB", "0xdd0f28e19C1780eb6396170735D45153D261490d",
              "0x2371e134e3455e0593363cBF89d3b6cf53740618", "0x78Fc2c2eD1A4cDb5402365934aE5648aDAd094d0",
              "0xbEef047a543E45807105E51A8BBEFCc5950fcfBa"]
SEAPORT = ["0x00000000006c3852cbEf3e08E8dF289169EdE581", "0x00000000000001ad428e4906aE43D8F9852d0dD6",
           "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC", "0x0000000000000068F116a894984e2DB1123eB395"]


def F(group, addrs, sigs, start, mode, window, flt=None):
    return {"group": group, "addrs": addrs, "sigs": sigs, "start": start, "mode": mode, "window": window, "flt": flt}


FAMILIES = {
    # withdrawal / redemption claims
    "lido_withdrawal_claim": F("withdrawals", ["0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1"],
                               ["WithdrawalClaimed(uint256,address,address,uint256)"], 17_266_000, "rpc", 100),
    "reth_burn": F("withdrawals", ["0xae78736Cd615f374D3085123A210448E74Fc6393"],
                   ["TokensBurned(address,uint256,uint256,uint256)"], 13_325_000, "es", 20_000),
    "eigenlayer_withdrawal_completed": F("withdrawals", ["0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A"],
                                         ["WithdrawalCompleted(bytes32)", "SlashingWithdrawalCompleted(bytes32)"],
                                         19_492_000, "es", 10_000),
    "etherfi_withdrawal_claim": F("withdrawals", ["0x7d5706f6ef3F89B3951E23e557CDFBC3239D4E2c"],
                                  ["WithdrawRequestClaimed(uint32,uint256,uint256,address,uint256)",
                                   "WithdrawRequestClaimed(uint32,uint256,uint256,address)"], 18_700_000, "es", 10_000),
    # ERC-4626 / savings vaults
    "sdai_vault": F("vaults", ["0x83F20F44975D03b1b09e64809B757c47f942BEeA"], E4626, 16_428_000, "rpc", 100),
    "susde_vault": F("vaults", ["0x9D39A5DE30e57443BfF2A8307A4256c8797A3497"], E4626, 18_571_000, "rpc", 100),
    "susds_vault": F("vaults", ["0xa3931d71877C0E7a3148CB7Eb4463524FEc27fbD"], E4626, 20_770_000, "rpc", 100),
    "yearn_v3_vault": F("vaults", YEARN_V3, E4626, 19_400_000, "es", 20_000),
    "metamorpho_vault": F("vaults", METAMORPHO, E4626, 19_000_000, "rpc", 100),
    # lending flows
    "aave_v3_ops": F("lending", [AAVE_POOL], AAVE, 16_291_000, "rpc", 20),
    "spark_ops": F("lending", [SPARK_POOL], AAVE, 16_776_000, "rpc", 100),
    "compound_v3_ops": F("lending", COMETS, ["Supply(address,address,uint256)", "Withdraw(address,address,uint256)",
                                             "SupplyCollateral(address,address,address,uint256)",
                                             "WithdrawCollateral(address,address,address,uint256)"],
                         15_331_000, "rpc", 50),
    "morpho_blue_ops": F("lending", [MORPHO], ["Supply(bytes32,address,address,uint256,uint256)",
                                               "Withdraw(bytes32,address,address,address,uint256,uint256)",
                                               "Borrow(bytes32,address,address,address,uint256,uint256)",
                                               "Repay(bytes32,address,address,uint256,uint256)",
                                               "SupplyCollateral(bytes32,address,address,uint256)",
                                               "WithdrawCollateral(bytes32,address,address,address,uint256)"],
                         18_883_000, "rpc", 50),
    # liquidations
    "liq_aave_v3": F("liquidations", [AAVE_POOL], ["LiquidationCall(address,address,address,uint256,uint256,address,bool)"],
                     16_291_000, "es", 20_000),
    "liq_spark": F("liquidations", [SPARK_POOL], ["LiquidationCall(address,address,address,uint256,uint256,address,bool)"],
                   16_776_000, "es", 50_000),
    "liq_compound_v2": F("liquidations", None, ["LiquidateBorrow(address,address,uint256,address,uint256)"],
                         11_565_000, "es", 20_000, "comp2"),
    "liq_compound_v3": F("liquidations", COMETS, ["AbsorbDebt(address,address,uint256,uint256)"], 15_331_000, "es", 50_000),
    "liq_morpho_blue": F("liquidations", [MORPHO], ["Liquidate(bytes32,address,address,uint256,uint256,uint256,uint256,uint256)"],
                         18_883_000, "es", 50_000),
    "liq_liquity": F("liquidations", ["0xA39739EF8b0231DbFA0DcdA07d7e29faAbCf4bb2"],
                     ["Liquidation(uint256,uint256,uint256,uint256)"], 12_178_000, "es", 50_000),
    # DEX swaps
    "uniswap_v2_swap": F("dex", None, [UNI2_SWAP], 11_565_000, "rpc", 2, "uni2"),
    "uniswap_v3_swap": F("dex", None, [UNI3_SWAP], 12_370_000, "rpc", 2, "uni3"),
    "uniswap_v4_swap": F("dex", ["0x000000000004444c5dc75cB358380D2e3dE08A90"],
                         ["Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)"], 21_688_400, "rpc", 10),
    "curve_exchange": F("dex", None, ["TokenExchange(address,int128,uint256,int128,uint256)",
                                      "TokenExchange(address,uint256,uint256,uint256,uint256)",
                                      "TokenExchangeUnderlying(address,int128,uint256,int128,uint256)"], 11_565_000, "rpc", 10),
    "balancer_swap": F("dex", [BAL_VAULT], ["Swap(bytes32,address,address,uint256,uint256)"], 12_272_000, "rpc", 10),
    # aggregator routes (tx.to = router)
    "agg_1inch": F("aggregators", ["0x1111111254EEB25477B68fb85Ed929f73A960582", "0x111111125421cA6dc452d289314280a0f8842A65",
                                   "0x1111111254fb6c44bAC0beD2854e76F90643097d"], None, 11_565_000, "to", 6),
    "agg_0x": F("aggregators", ["0xDef1C0ded9bec7F1a1670819833240f027b25EfF"], None, 11_600_000, "to", 6),
    "agg_cow": F("aggregators", ["0x9008D19f58AAbD9eD0D60971565AA8510560ab41"], ["Settlement(address)"], 12_593_000, "rpc", 50),
    "agg_paraswap": F("aggregators", ["0xDEF171Fe48CF0115B1d80b88dc8eAB4f0B1a3f00", "0x6A000F20005980200259B80c5102003040001068"],
                      None, 12_300_000, "to", 10),
    "agg_odos": F("aggregators", ["0xCf5540fFFCdC3d510B18bFcA6d2b9987b0772559"], None, 17_700_000, "to", 10),
    "agg_universal_router": F("aggregators", ["0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B", "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                                              "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"], None, 16_100_000, "to", 3),
    # flash loans
    "fl_balancer": F("flash_loans", [BAL_VAULT], ["FlashLoan(address,address,uint256,uint256)"], 12_272_000, "es", 5_000),
    "fl_aave_v3": F("flash_loans", [AAVE_POOL], ["FlashLoan(address,address,address,uint256,uint8,uint256,uint16)"],
                    16_291_000, "es", 5_000),
    "fl_morpho": F("flash_loans", [MORPHO], ["FlashLoan(address,address,uint256)"], 18_883_000, "es", 5_000),
    "fl_uniswap_v3": F("flash_loans", None, ["Flash(address,address,uint256,uint256,uint256,uint256)"],
                       12_370_000, "rpc", 100, "uni3"),
    "fl_maker": F("flash_loans", ["0x60744434d6339a6B27d73d9Eda62b6F66a0a04FA"], ["FlashLoan(address,address,uint256,uint256)"],
                  13_200_000, "es", 50_000),
    # staking / restaking deposits
    "lido_submit": F("staking", ["0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84"], ["Submitted(address,uint256,address)"],
                     11_565_000, "rpc", 100),
    "reth_mint": F("staking", ["0xae78736Cd615f374D3085123A210448E74Fc6393"], ["TokensMinted(address,uint256,uint256,uint256)"],
                   13_325_000, "es", 20_000),
    "eigenlayer_deposit": F("staking", ["0x858646372CC42E1A627fcE94aa7A7033e7CF075A"],
                            ["Deposit(address,address,address,uint256)", "Deposit(address,address,uint256)"],
                            17_445_000, "es", 10_000),
    "etherfi_deposit": F("staking", ["0x308861A430be4cce5502d0A12724771Fc6DaF216"], ["Deposit(address,uint256,uint8,address)"],
                         17_664_000, "es", 10_000),
    # bridges
    "bridge_across": F("bridges", ["0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5"], None, 17_100_000, "to", 10),
    "bridge_stargate": F("bridges", ["0x8731d54E9D02c286767d56ac03e8037C07e01e98", "0x77b2043768d28E9C9aB44E1aBfC95944bcE57931",
                                     "0xc026395860Db2d07ee33e05fE50ed7bD583189C7"], None, 14_403_000, "to", 15),
    "bridge_arbitrum": F("bridges", ["0x8315177aB297bA92A06054cE80a67Ed4DBd7ed3a"],
                         ["MessageDelivered(uint256,bytes32,address,uint8,address,bytes32,uint256,uint64)"],
                         12_525_000, "es", 3_000),
    "bridge_optimism": F("bridges", ["0xbEb5Fc579115071764c7423A4f12eDde41f106Ed"],
                         ["TransactionDeposited(address,address,uint256,bytes)"], 17_422_000, "es", 3_000),
    "bridge_base": F("bridges", ["0x49048044D57e1C92A77f79988d21Fa8fAF74E97e"],
                     ["TransactionDeposited(address,address,uint256,bytes)"], 17_482_000, "es", 3_000),
    # NFT marketplaces
    "nft_seaport": F("nft", SEAPORT, ["OrderFulfilled(bytes32,address,address,address,(uint8,address,uint256,uint256)[],"
                                      "(uint8,address,uint256,uint256,address)[])"], 14_946_000, "rpc", 20),
    "nft_blur": F("nft", ["0x000000000000Ad05Ccc4F10045630fb830B95127", "0xb2ecfE4E4D61f8790bbb9DE2D1259B9e2410CEA5"],
                  None, 15_779_000, "to", 15),
    # Safe multisig executions
    "safe_exec": F("safe", None, ["ExecutionSuccess(bytes32,uint256)"], 11_565_000, "rpc", 5),
    # governance timelock executions
    "timelock_compound": F("governance", None, ["ExecuteTransaction(bytes32,address,uint256,string,bytes,uint256)"],
                           11_565_000, "es", 20_000),
    "timelock_oz": F("governance", None, ["CallExecuted(bytes32,uint256,address,uint256,bytes)"], 11_565_000, "es", 5_000),
    # MEV bots: unverified bot contracts trading directly on Uniswap pools
    "mev_bot_uni_v2": F("mev_bots", None, [UNI2_SWAP], 11_565_000, "rpc", 2, "uni2+unverified_to"),
    "mev_bot_uni_v3": F("mev_bots", None, [UNI3_SWAP], 12_370_000, "rpc", 2, "uni3+unverified_to"),
}
GROUP_TARGET = 120

_lock = threading.Lock()
_call_cache: dict = {}
_verified_to: set = {a.lower() for a in ("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
                                         "0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B", "0xE592427A0AEce92De3Edee1F18E0157C05861564",
                                         "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af")}
_logs_client = None


def logs_client():
    global _logs_client
    with _lock:
        if _logs_client is None:
            _logs_client = Drpc("eth")  # separate rate-limit budget from the trace client
        return _logs_client


def eth_call(to: str, data: str) -> str | None:
    key = (to, data)
    if key not in _call_cache:
        try:
            _call_cache[key] = cm.rpc("eth").rpc("eth_call", [{"to": to, "data": data}, "latest"])
        except RuntimeError:
            _call_cache[key] = None
    return _call_cache[key]


def addr_of(word: str | None) -> str | None:
    return ("0x" + word[-40:]).lower() if word and len(word) >= 42 else None


def passes(flt: str | None, log_addr: str, tx_to: str | None) -> bool:
    if not flt:
        return True
    for f in flt.split("+"):
        if f == "uni2" and addr_of(eth_call(log_addr, "0xc45a0155")) != UNI2_FACTORY:
            return False
        if f == "uni3" and addr_of(eth_call(log_addr, "0xc45a0155")) != UNI3_FACTORY:
            return False
        if f == "comp2" and addr_of(eth_call(log_addr, "0x5fe3b567")) != COMPTROLLER:
            return False
        if f == "unverified_to":
            if not tx_to:
                return False
            code = cm.rpc("eth").rpc("eth_getCode", [tx_to, "latest"])
            if not code or code == "0x" or cm.etherscan("eth").source(tx_to)["verified"]:
                return False
    return True


def candidates(spec, b, rng):
    """[(tx_hash, protected_contract)] for one random window starting at block b."""
    mode, window = spec["mode"], spec["window"]
    if mode == "to":
        targets = {a.lower() for a in spec["addrs"]}
        for n in range(b, b + window):
            block = cm.rpc("eth").rpc("eth_getBlockByNumber", [hex(n), True], cache=False)
            txs = [t for t in block.get("transactions", [])
                   if (t.get("to") or "").lower() in targets and len(t.get("input", "")) > 10]
            if txs:
                t = rng.choice(txs)
                return [(t["hash"].lower(), t["to"].lower())]
        return []
    topics = [ev(s) for s in spec["sigs"]]
    if mode == "rpc":
        flt = {"fromBlock": hex(b), "toBlock": hex(b + window), "topics": [topics]}
        if spec["addrs"]:
            flt["address"] = spec["addrs"]
        logs = logs_client().rpc("eth_getLogs", [flt], cache=False)
    else:
        params = {"module": "logs", "action": "getLogs", "topic0": rng.choice(topics), "fromBlock": b,
                  "toBlock": b + window, "page": 1, "offset": 100}
        if spec["addrs"]:
            params["address"] = rng.choice(spec["addrs"])
        body = cm.etherscan("eth").call(**params)
        logs = body.get("result") if isinstance(body.get("result"), list) else []
    if not logs:
        return []
    if spec["flt"] and "unverified_to" in spec["flt"]:  # keep swaps whose tx.to is a contract nobody verified
        to_of = {}
        for n in range(b, b + window + 1):
            blk = cm.rpc("eth").rpc("eth_getBlockByNumber", [hex(n), True], cache=False)
            to_of.update({t["hash"].lower(): (t.get("to") or "").lower() for t in blk.get("transactions", [])})
        es = cm.etherscan("eth")
        keep = []
        for lg in logs:
            to = to_of.get(lg["transactionHash"].lower())
            if to and to not in _verified_to:
                keep.append(lg)
        rng.shuffle(keep)
        out = []
        for lg in keep:
            to = to_of[lg["transactionHash"].lower()]
            if es.source(to)["verified"]:
                _verified_to.add(to)
                continue
            out.append(lg)
            if len(out) >= 3:
                break
        logs = out
    rng.shuffle(logs)
    return [(lg["transactionHash"].lower(), lg["address"].lower()) for lg in logs[:3]]


def check():
    es = cm.etherscan("eth")
    head = int(cm.rpc("eth").rpc("eth_blockNumber", [], cache=False), 16)
    for name, spec in FAMILIES.items():
        names = [(a[:10], es.source(a)["name"], es.source(a)["verified"]) for a in (spec["addrs"] or [])]
        n = None
        if spec["sigs"]:
            params = {"module": "logs", "action": "getLogs", "topic0": ev(spec["sigs"][0]),
                      "fromBlock": max(spec["start"], head - 400_000), "toBlock": head, "page": 1, "offset": 50}
            if spec["addrs"]:
                params["address"] = spec["addrs"][0]
            body = es.call(**params)
            n = len(body["result"]) if isinstance(body.get("result"), list) else body.get("result")
        print(f"{name:34s} {spec['mode']:4s} logs(recent)={n} {names}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--group-target", type=int, default=GROUP_TARGET)
    args = ap.parse_args()
    if args.check:
        return check()
    head = int(cm.rpc("eth").rpc("eth_blockNumber", [], cache=False), 16) - 50
    excluded = cm.used_hashes() | cm.preexisting_replays()
    have = [json.loads(l) for l in open(OUT)] if OUT.exists() else []
    done = {r["tx_hash"] for r in have}
    per_group = {}
    for spec in FAMILIES.values():
        per_group[spec["group"]] = per_group.get(spec["group"], 0) + 1
    es = cm.etherscan("eth")

    def sample(name):
        spec = FAMILIES[name]
        target = math.ceil(args.group_target / per_group[spec["group"]])
        got = sum(1 for r in have if r["source"] == name)
        rng = random.Random(f"{SEED}:{name}:{got}")
        tries, errors = 0, 0
        lo = max(spec["start"], LO)
        while got < target and tries < target * 10:
            tries += 1
            b = rng.randrange(lo, head - spec["window"])
            try:
                cands = candidates(spec, b, rng)
            except Exception:  # noqa: BLE001
                errors += 1
                continue
            for h, protected in cands:
                if h in excluded:
                    continue
                with _lock:
                    if h in done:
                        continue
                try:
                    if not es.source(protected)["verified"]:
                        continue
                    tx = cm.rpc("eth").tx(h)
                    if not passes(spec["flt"], protected, (tx.get("to") or "").lower() or None):
                        continue
                    rec = cm.replay_and_store("eth", h, allow_replay=False)
                except Exception:  # noqa: BLE001
                    errors += 1
                    continue
                if not (rec and rec["ok"] and rec.get("source") == "mainnet_trace"):
                    continue
                with _lock:
                    if h in done:
                        continue
                    done.add(h)
                    iid = f"test4:{name}:{h[:10]}"
                    row = {"incident": iid, "source": name, "family": spec["group"], "tx_hash": h, "label": 0,
                           "chain": "eth", "block": int(rec["tx"]["blockNumber"], 16), "victim": protected,
                           "group": iid, "trace_source": "mainnet_trace"}
                    with OUT.open("a") as fh:
                        fh.write(json.dumps(row) + "\n")
                got += 1
                break  # one tx per window
        print(f"{name}: {got}/{target} (windows={tries}, errors={errors})", flush=True)

    names = args.only or list(FAMILIES)
    # interleave groups so throughput is spread across sources
    with ThreadPoolExecutor(args.workers) as pool:
        for f in [pool.submit(sample, n) for n in names]:
            try:
                f.result()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
    print(f"done: {len(done)} rows -> {OUT}")


if __name__ == "__main__":
    main()
