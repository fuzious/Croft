"""Matching normals (label 0) for the user-harm / NFT / vault set: NFT trades with real payment, NFT lending,
owner setApprovalForAll, NFT mints; vault deposits/withdrawals, Curve/Convex LP, Uniswap V2 LP add/remove.

Sampling: random block windows over each source's lifetime; Etherscan txlist on the contract (direct calls,
filtered by function name) or getLogs (mints). Every kept tx is traced exactly (dRPC) and checked on its receipt.

    HARM_ES_RATE=1.2 uv run python scripts/harm_normals.py
"""
import argparse
import json
import random
import re
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import harm_common as hc

OUT = hc.DATA / "harm_normals.jsonl"
LATEST = 26_150_000
TRADE = "trade"
# name: (kind, contract, start, end|None, window, function-name regex, check)
SOURCES = {
    "seaport_1_1": ("normal_nft", "0x00000000006c3852cbEf3e08E8dF289169EdE581", 14_946_474, 17_600_000, 200, r"^(fulfill|match)", TRADE),
    "seaport_1_4": ("normal_nft", "0x00000000000001ad428e4906aE43D8F9852d0dD6", 16_655_960, 17_900_000, 300, r"^(fulfill|match)", TRADE),
    "seaport_1_5": ("normal_nft", "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC", 17_129_405, None, 300, r"^(fulfill|match)", TRADE),
    "seaport_1_6": ("normal_nft", "0x0000000000000068F116a894984e2DB1123eB395", 19_442_152, None, 300, r"^(fulfill|match)", TRADE),
    "blur_v1": ("normal_nft", "0x000000000000Ad05Ccc4F10045630fb830B95127", 15_700_000, None, 200, r"^(execute|bulkExecute)", TRADE),
    "blur_v2": ("normal_nft", "0xb2ecfE4E4D61f8790bbb9DE2D1259B9e2410CEA5", 17_603_892, None, 200, r"^take", TRADE),
    "looksrare_v1": ("normal_nft", "0x59728544B08AB483533076417FbBB2fD0B17CE3a", 13_885_625, 18_500_000, 400, r"^match", TRADE),
    "looksrare_v2": ("normal_nft", "0x0000000000E655fAe4d56241588680F86E3b2377", 17_200_000, None, 1000, r"^execute", TRADE),
    "x2y2": ("normal_nft", "0x74312363e45DCaBA76c59ec49a7Aa8A65a67EeD3", 14_000_000, 18_500_000, 500, r"^run", TRADE),
    "blur_blend": ("normal_nft", "0x29469395eAf6f95920E59F858042f0e28D98a20B", 17_163_167, None, 500, r"^(borrow|repay|refinance|buyLocked|takeBid)", None),
    "benddao_lendpool": ("normal_nft", "0x70b97A0da65C15dfb0FFA02aEE6FA36e507C2762", 14_417_009, None, 5000, r"^(borrow|repay|auction|redeem|liquidate)", None),
    "benddao_weth_gateway": ("normal_nft", "0x3B968D2D299B895A5Fcf3BBa7A64ad0F566e6F88", 14_417_009, None, 3000, r"^(borrow|repay|batchBorrow|batchRepay)", None),
    "approve_bayc": ("normal_nft", "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D", 12_287_507, None, 20000, r"^setApprovalForAll", "approval"),
    "approve_mayc": ("normal_nft", "0x60E4d786628Fea6478F785A6d7e704777c86a7c6", 13_117_000, None, 20000, r"^setApprovalForAll", "approval"),
    "approve_azuki": ("normal_nft", "0xED5AF388653567Af2F388E6224dC7C4b3241C544", 13_975_838, None, 20000, r"^setApprovalForAll", "approval"),
    "approve_pudgy": ("normal_nft", "0xBd3531dA5CF5857e7CfAA92426877b022e612cf8", 12_876_179, None, 20000, r"^setApprovalForAll", "approval"),
    "approve_doodles": ("normal_nft", "0x8a90CAb2b38dba80c64b7734e58Ee1dB38B8992e", 12_878_194, None, 20000, r"^setApprovalForAll", "approval"),
    "approve_milady": ("normal_nft", "0x5Af0D9827E0c53E4799BB226655A1de152A425a5", 13_090_020, None, 20000, r"^setApprovalForAll", "approval"),
    "nft_mint": ("normal_nft", None, 13_000_000, None, 3, None, "mint"),
    "yearn_v2_usdc": ("normal_vault", "0xa354F35829Ae975e850e23e9615b11Da1B3dC4DE", 12_800_000, None, 30000, r"^(deposit|withdraw)", None),
    "yearn_v2_dai": ("normal_vault", "0xdA816459F1AB5631232FE5e97a05BBBb94970c95", 12_800_000, None, 30000, r"^(deposit|withdraw)", None),
    "yearn_v2_weth": ("normal_vault", "0xa258C4606Ca8206D8aA700cE2143D7db854D168c", 12_800_000, None, 30000, r"^(deposit|withdraw)", None),
    "yearn_v3_usdc": ("normal_vault", "0xBe53A109B494E5c9f97b9Cd39Fe969BE68BF6204", 19_419_991, None, 20000, r"^(deposit|withdraw|redeem|mint)", None),
    "metamorpho_steakhouse_usdc": ("normal_vault", "0xBEEF01735c132Ada46AA9aA4c54623cAA92A64CB", 18_928_285, None, 5000, r"^(deposit|withdraw|redeem|mint)", None),
    "metamorpho_gauntlet_weth": ("normal_vault", "0x2371e134e3455e0593363cBF89d3b6cf53740618", 19_372_149, None, 10000, r"^(deposit|withdraw|redeem|mint)", None),
    "susde": ("normal_vault", "0x9D39A5DE30e57443BfF2A8307A4256c8797A3497", 18_571_000, None, 1000, r"^(deposit|withdraw|redeem|mint|cooldown|unstake)", None),
    "sdai": ("normal_vault", "0x83F20F44975D03b1b09e64809B757c47f942BEeA", 16_428_000, None, 3000, r"^(deposit|withdraw|redeem|mint)", None),
    "susds": ("normal_vault", "0xa3931d71877C0E7a3148CB7Eb4463524FEc27fbD", 20_677_434, None, 3000, r"^(deposit|withdraw|redeem|mint)", None),
    "convex_booster": ("normal_vault", "0xF403C135812408BFbE8713b5A23a04b3D48AAE31", 12_450_000, None, 500, r"^(deposit|withdraw)", None),
    "curve_3pool": ("normal_vault", "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7", 10_809_473, None, 1000, r"^(add_liquidity|remove_liquidity)", None),
    "curve_steth": ("normal_vault", "0xDC24316b9AE028F1497c275EB9192a3Ea0f67022", 11_592_551, None, 2000, r"^(add_liquidity|remove_liquidity)", None),
    "univ2_lp": ("normal_vault", "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", 10_207_858, None, 100, r"^(addLiquidity|removeLiquidity)", None),
}
TARGET = {"normal_nft": 150, "normal_vault": 150}


def candidates(name, rng):
    kind, addr, start, end, window, rx, chk = SOURCES[name]
    end = end or LATEST
    w = window
    for _ in range(4):
        b = rng.randrange(start, end - w)
        if chk == "mint":
            body = hc.etherscan.call(module="logs", action="getLogs", topic0=hc.T_TRANSFER,
                                     topic1="0x" + "0" * 64, topic0_1_opr="and", fromBlock=b, toBlock=b + w,
                                     page=1, offset=200)
            logs = [lg for lg in (body.get("result") if isinstance(body.get("result"), list) else [])
                    if len(lg.get("topics") or []) == 4]
            if logs:
                rng.shuffle(logs)
                return [(lg["transactionHash"].lower(), lg["address"].lower()) for lg in logs[:5]]
        else:
            body = hc.etherscan.call(module="account", action="txlist", address=addr, startblock=b,
                                     endblock=b + w, page=1, offset=100, sort="asc")
            res = body.get("result") if isinstance(body.get("result"), list) else []
            ok = [t for t in res if t.get("isError") == "0" and (t.get("to") or "").lower() == addr.lower()
                  and re.search(rx, t.get("functionName") or "")]
            if ok:
                rng.shuffle(ok)
                return [(t["hash"].lower(), addr.lower()) for t in ok[:3]]
        w *= 3
    return []


def accept(name, protocol, tx, logs, rec=None):
    """Receipt-level check; for trades paid only in ETH by inner calls, needs the trace (rec)."""
    kind, addr, *_, chk = SOURCES[name]
    trs = hc.transfers(logs)
    nft = [t for t in trs if t["std"] != "erc20"]
    if chk == TRADE:
        paid = (int(tx.get("value") or "0x0", 16) > 0 or any(t["std"] == "erc20" and t["amount"] > 0 for t in trs)
                or (rec is not None and len(hc.eth_value_calls(rec["trace"])) > 1))
        return bool(nft) and paid
    if chk == "approval":
        return any((lg.get("topics") or [""])[0].lower() == hc.T_APPROVAL_ALL
                   and hc.addr_topic(lg["topics"][1]) == tx["from"].lower() for lg in logs)
    if chk == "mint":
        return ((tx.get("to") or "").lower() == protocol
                and any(t["from"] == hc.ZERO and t["to"] == tx["from"].lower() and t["token"] == protocol for t in nft)
                and hc.etherscan.source(protocol)["verified"])
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=11)
    args = ap.parse_args()
    used = hc.used_hashes()
    done = {json.loads(l)["tx_hash"] for l in open(OUT)} if OUT.exists() else set()
    have = Counter(json.loads(l)["source"] for l in open(OUT)) if OUT.exists() else Counter()
    lock = threading.Lock()
    per_kind = Counter(SOURCES[n][0] for n in SOURCES)

    def run(name):
        rng = random.Random(f"{args.seed}:{name}")
        kind = SOURCES[name][0]
        target = -(-TARGET[kind] // per_kind[kind])
        got, tries = have[name], 0
        while got < target and tries < target * 5:
            tries += 1
            try:
                cands = candidates(name, rng)
            except RuntimeError:
                continue
            for h, protocol in cands:
                with lock:
                    if h in used or h in done:
                        continue
                try:
                    tx, rc = hc.alchemy.tx(h), hc.alchemy.receipt(h)
                    if int(rc["status"], 16) != 1:
                        continue
                    pre = accept(name, protocol, tx, rc["logs"])
                    if not pre and SOURCES[name][-1] != TRADE:
                        continue
                    rec = hc.trace(h)
                    if not (rec and rec["ok"] and rec["matched"]):
                        continue
                    if not pre and not accept(name, protocol, rec["tx"], rec["logs"], rec):
                        continue
                except Exception as e:  # noqa: BLE001
                    print(f"[err] {name} {h}: {str(e)[:100]}", flush=True)
                    continue
                block = int(rec["tx"]["blockNumber"], 16)
                with lock:
                    if h in done:
                        continue
                    done.add(h)
                hc.append(OUT, {"incident": f"harm:{kind}:{name}:{h[:10]}", "kind": kind, "source": name,
                                "tx_hash": h, "label": 0, "chain": "eth", "block": block,
                                "month": hc.month_of(block), "victim": protocol, "group": f"{kind}:{name}"})
                got += 1
                break
        print(f"{name}: {got}/{target} ({tries} tries)", flush=True)

    with ThreadPoolExecutor(3) as pool:
        list(pool.map(run, SOURCES))
    rows = [json.loads(l) for l in open(OUT)]
    print("normals", Counter(r["kind"] for r in rows), Counter(r["month"][:4] for r in rows))


if __name__ == "__main__":
    main()
