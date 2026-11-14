"""Smoke test: load Laya on this machine, run the tx question panel on hand-written fact cards, time it.

Checks plumbing and latency only. Base Laya is near chance zero-shot (model card), so the answers
are not a quality signal. The fact cards are synthetic illustrations, not real transactions.

    uv run python scripts/laya_smoke.py [--device mps|cpu] [--subfolder typed-decisions]
"""
import argparse
import json
import statistics
import time

import laya

QUESTIONS = {
    "sender_profits_from_protocol": {
        "type": "noul",
        "instructions": "The transaction sender ends with a large net USD gain, and the losers are "
                        "protocol-owned contracts or pools rather than trading counterparties.",
    },
    "flashloan_price_manipulation": {
        "type": "noul",
        "instructions": "A flash loan funds the transaction and a price the protocol relies on moves "
                        "sharply inside the same transaction.",
    },
    "unauthorized_privileged_call": {
        "type": "noul",
        "instructions": "A privileged function (upgrade, owner change, mint, withdraw all) is called "
                        "by an address that is not the documented admin.",
    },
    "explained_by_mev": {
        "type": "noul",
        "instructions": "The activity is better explained as ordinary MEV such as arbitrage, "
                        "liquidation or backrunning than as an exploit.",
    },
    "severity": {
        "type": "score",
        "instructions": "How severe is the risk this transaction poses to the protocol or its users?",
        "criteria": ["none", "low", "medium", "high", "critical"],
    },
    "verdict": {
        "type": "choice",
        "instructions": "Should this transaction be allowed to execute?",
        "criteria": {
            "allow": "Normal activity, no meaningful risk.",
            "review": "Unusual or ambiguous; a human should look before it executes.",
            "block": "Very likely an exploit or theft; stop it.",
        },
    },
}

FACT_CARDS = {
    "exploit_like": {
        "sender": {"label": "fresh EOA, funded 2h ago via mixer", "age_blocks": 600},
        "target_protocol": "lending market (verified, TVL $180M)",
        "flash_loans": [{"source": "Aave V3", "asset": "DAI", "usd": 30_000_000}],
        "steps": ["deposit DAI", "borrow 10x leverage", "donate collateral to reserves",
                  "self-liquidate at discount", "repay flash loan"],
        "net_usd_change": {"sender": 9_400_000, "lending market pools": -9_400_000},
        "price_moves_in_tx": [],
        "privileged_calls": [],
        "funds_destination": "new contract deployed 3 blocks earlier",
    },
    "arbitrage_like": {
        "sender": {"label": "known MEV searcher bot", "age_blocks": 2_100_000},
        "target_protocol": "Uniswap V3 + Curve pools",
        "flash_loans": [{"source": "Balancer", "asset": "WETH", "usd": 4_000_000}],
        "steps": ["swap WETH->USDC on Uniswap V3", "swap USDC->WETH on Curve", "repay flash loan"],
        "net_usd_change": {"sender": 1_850, "Uniswap V3 pool": -900, "Curve pool": -950},
        "price_moves_in_tx": [{"pool": "Uniswap V3 WETH/USDC", "move_pct": 0.08}],
        "privileged_calls": [],
        "funds_destination": "sender",
    },
    "plain_swap": {
        "sender": {"label": "retail EOA", "age_blocks": 3_400_000},
        "target_protocol": "Uniswap Universal Router",
        "flash_loans": [],
        "steps": ["swap 1.2 ETH -> USDC"],
        "net_usd_change": {"sender": -6, "Uniswap V3 pool": 6},
        "price_moves_in_tx": [],
        "privileged_calls": [],
        "funds_destination": "sender",
    },
}


def summarize(answers):
    out = {}
    for qid, a in answers.items():
        if a.get("type") == "noul" or "noul" in a:
            out[qid] = round(a["noul"], 3)
        elif "choice" in a:
            out[qid] = (a["choice"], round(a.get("confidence", 0), 3))
        elif "score" in a:
            out[qid] = (round(a["score"], 2), round(a.get("confidence", 0), 3))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", default="mps")
    ap.add_argument("--subfolder", default="typed-decisions")
    ap.add_argument("--runs", type=int, default=20)
    args = ap.parse_args()

    t0 = time.perf_counter()
    agent = laya.load("convaiinnovations/laya", subfolder=args.subfolder, device=args.device)
    print(f"loaded {args.subfolder} on {args.device} in {time.perf_counter() - t0:.1f}s "
          f"(max_len={agent.cfg.get('max_len')}, head_max_len={agent.cfg.get('head_max_len')})")

    for name, card in FACT_CARDS.items():
        n_tokens = len(agent.tok(json.dumps(card, ensure_ascii=False))["input_ids"])
        agent.system_one(card, QUESTIONS)  # warm-up
        times = []
        for _ in range(args.runs):
            t = time.perf_counter()
            res = agent.system_one(card, QUESTIONS)
            times.append((time.perf_counter() - t) * 1000)
        times.sort()
        p95 = times[int(0.95 * (len(times) - 1))]
        print(f"\n[{name}] state≈{n_tokens} tokens, {len(QUESTIONS)} questions | "
              f"p50 {statistics.median(times):.1f} ms, p95 {p95:.1f} ms")
        for qid, v in summarize(res["answers"]).items():
            print(f"  {qid:32s} {v}")


if __name__ == "__main__":
    main()
