"""Build fact cards + numeric features for every replayed row in data/dataset.jsonl.

    uv run python scripts/make_cards.py --version v1
Writes data/cards_<version>.jsonl; per-tx results are cached under data/cards/<version>/.
"""
import argparse
import json
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from oracle.card import CardBuilder
from oracle.category import HARDNEG_CATEGORY, categorize
from oracle.sources import Alchemy, Etherscan, Prices

ROOT = Path(__file__).resolve().parents[1]
# For hard negatives the "protected protocol" is the protocol the tx was sampled from.
HARDNEG_PROTECTED = {
    "balancer_flashloan": "0xba12222222228d8ba445958a75a0704d566bf2c8",
    "aave_v3_flashloan": "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
    "aave_v3_liquidation": "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
    "morpho_flashloan": "0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb",
    "uniswap_universal_router": "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad",
    "oneinch_v5_router": "0x1111111254eeb25477b68fb85ed929f73a960582",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--rows", default=None, help="explicit jsonl of rows to card (instead of data/dataset*.jsonl)")
    args = ap.parse_args()
    cache = ROOT / "data" / "cards" / args.version
    cache.mkdir(parents=True, exist_ok=True)
    files = ([Path(args.rows)] if args.rows else
             sorted(p for p in (ROOT / "data").glob("dataset*.jsonl") if "skips" not in p.name))
    rows = [json.loads(l) for f in files for l in open(f)]
    seen: set[str] = set()
    rows = [r for r in rows if not (r["tx_hash"] in seen or seen.add(r["tx_hash"]))]  # one row per tx
    builders = {c: CardBuilder.for_chain(c) for c in ("eth", "bsc", "base", "polygon", "arbitrum", "optimism")}

    # Protected set per incident = listed victim + the verified contract that lost most in the exploit.
    def protected_set(row):
        rp = json.loads((ROOT / "data" / "replays" / f"{row['tx_hash']}.json").read_text())
        try:
            _, _, meta = builders[row.get("chain", "eth")].build(rp, protected=[row["victim"]])
        except Exception:  # noqa: BLE001
            meta = {"losers": []}
        extra = [l["addr"] for l in meta["losers"] if l["kind"] == "verified"][:1]
        extra += [l["addr"] for l in meta.get("nft_losers", [])][:1]  # NFT drains have no USD price to rank by
        return row["incident"], list(dict.fromkeys([row["victim"].lower()] + extra))

    with ThreadPoolExecutor(args.workers) as pool:
        protected_by_incident = dict(pool.map(protected_set, [r for r in rows if r["label"] == 1 and r.get("victim")]))

    def one(row):
        path = cache / f"{row['tx_hash']}.json"
        if path.exists():
            return json.loads(path.read_text())
        rp = json.loads((ROOT / "data" / "replays" / f"{row['tx_hash']}.json").read_text())
        cb = builders[row.get("chain", "eth")]
        try:
            protected = (row.get("protected") or protected_by_incident.get(row["incident"])
                         or ([row["victim"]] if row.get("victim") else None) or [HARDNEG_PROTECTED[row["source"]]])
            category = row.get("category") or (categorize(cb.etherscan, protected[-1]) if row.get("victim")
                                               else HARDNEG_CATEGORY.get(row.get("source"), "unknown"))
            card, feats, meta = cb.build(rp, protected=protected, category=category)
        except Exception:  # noqa: BLE001
            print(f"[card error] {row['tx_hash']}\n{traceback.format_exc(limit=3)}", flush=True)
            return None
        out = {**row, "protected": protected, "category": category, "card": card, "feats": feats, "meta": meta}
        path.write_text(json.dumps(out))
        return out

    with ThreadPoolExecutor(args.workers) as pool:
        results = [r for r in pool.map(one, rows) if r]
    out = ROOT / "data" / f"cards_{args.version}.jsonl"
    out.write_text("".join(json.dumps(r) + "\n" for r in results))
    n_ex = sum(r["label"] for r in results)
    print(f"{len(results)} cards ({n_ex} exploit / {len(results) - n_ex} normal) -> {out}")


if __name__ == "__main__":
    main()
