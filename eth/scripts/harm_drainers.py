"""Wallet-drainer / phishing txs (label 1, user harm) from public scam-address lists (parsed as text only).

Sources (untrusted data, own dirs under data/raw/):
  ScamSniffer scam-database  https://github.com/scamsniffer/scam-database  (blacklist/all.json, combined.json)
  Forta labelled-datasets    https://github.com/forta-network/labelled-datasets (labels/1/phishing_scams.csv)

For listed addresses X: Etherscan token/NFT/1155 transfers into X and normal txs to X give candidate txs.
A candidate is kept only if (receipt) some EOA victim V, which is neither tx.from nor tx.to nor listed, sends
a real asset (priced ERC-20 worth >= $1, or an ERC-721/1155 of a verified collection) to the drainer side
(a listed address, tx.from, or an unverified non-infrastructure tx.to), and V receives nothing back in the
tx (no token transfer to V in logs, no ETH to V in the trace).

Groups: union-find over the listed address, listed recipients, the operator (tx.from), the drainer contract
(tx.to when unverified and not infrastructure) and ScamSniffer domain co-listing.

    uv run python scripts/harm_drainers.py --addresses 500 --target 220
"""
import argparse
import csv
import json
import random
import threading
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

import harm_common as hc
from oracle.sources import Prices

RAW = hc.DATA / "raw"
POOL = hc.DATA / "harm_drainer_pool.jsonl"   # verified candidates (pre-trace)
OUT = hc.DATA / "harm_drainers.jsonl"
INFRA = {a.lower() for a in [
    "0x00000000006c3852cbEf3e08E8dF289169EdE581", "0x00000000000001ad428e4906aE43D8F9852d0dD6",
    "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC", "0x0000000000000068F116a894984e2DB1123eB395",  # Seaport
    "0x000000000022D473030F116dDEE9F6B43aC78BA3",  # Permit2
    "0x000000000000Ad05Ccc4F10045630fb830B95127", "0xb2ecfE4E4D61f8790bbb9DE2D1259B9e2410CEA5",  # Blur
    "0x74312363e45DCaBA76c59ec49a7Aa8A65a67EeD3", "0x59728544B08AB483533076417FbBB2fD0B17CE3a",
    "0x0000000000E655fAe4d56241588680F86E3b2377", "0xcA11bde05977b3631167028862bE2a173976CA11",
    "0x7f268357A8c2552623316e2562D90e642bB538E5", "0x7Be8076f4EA4A4AD08075C2508e481d6C946D12b",  # Wyvern
    "0x1E0049783F008A0085193E00003D00cd54003c71",  # OpenSea conduit
]}
prices = Prices("eth")


def load_lists():
    ss = RAW / "scam-database/repo/blacklist"
    listed = {a.lower() for a in json.loads((ss / "all.json").read_text())["address"]}
    listed |= {a.lower() for a in json.loads((ss / "address.json").read_text())}
    domains = defaultdict(set)
    for dom, addrs in json.loads((ss / "combined.json").read_text()).items():
        for a in addrs:
            domains[a.lower()].add(dom)
            listed.add(a.lower())
    src = {a: "scamsniffer" for a in listed}
    with open(RAW / "forta-labelled-datasets/repo/labels/1/phishing_scams.csv") as fh:
        for r in csv.DictReader(fh):
            a = (r.get("address") or "").lower()
            if len(a) == 42:
                listed.add(a)
                src.setdefault(a, "forta:" + (r.get("etherscan_tag") or "")[:40])
    return listed, domains, src


def es_list(action: str, address: str, sort: str, offset: int = 60) -> list:
    try:
        body = hc.etherscan.call(module="account", action=action, address=address, startblock=0,
                                 endblock=99_999_999, page=1, offset=offset, sort=sort)
    except RuntimeError:
        return []
    res = body.get("result")
    return res if isinstance(res, list) else []


_dec: dict = {}


def decimals(token: str) -> int | None:
    if token not in _dec:
        try:
            r = hc.alchemy.rpc("eth_call", [{"to": token, "data": "0x313ce567"}, "latest"])
            _dec[token] = int(r, 16) if r and r != "0x" and len(r) <= 66 else None
        except RuntimeError:
            _dec[token] = None
    return _dec[token]


def usd_value(token: str, amount: int, ts: int) -> float | None:
    d = decimals(token)
    if d is None or d > 36:
        return None
    try:
        p = prices.usd([token], ts).get(token)
    except Exception:  # noqa: BLE001
        return None
    return None if p is None else amount / 10 ** d * p


def verified(addr: str) -> bool:
    try:
        return hc.etherscan.source(addr)["verified"]
    except RuntimeError:
        return False


def check(h: str, listed: set) -> dict | None:
    tx = hc.alchemy.tx(h)
    if not tx or not tx.get("to"):
        return None
    rc = hc.alchemy.receipt(h)
    if not rc or int(rc["status"], 16) != 1:
        return None
    sender, to = tx["from"].lower(), tx["to"].lower()
    trs = hc.transfers(rc["logs"])
    emitters = {t["token"] for t in trs}
    # ScamSniffer's domain->address map also lists legit contracts a phishing site touched (e.g. USDT)
    to_is_drainer = to not in INFRA and to not in emitters and (to in listed or not verified(to))
    side = (listed - emitters - INFRA) | {sender} | ({to} if to_is_drainer else set())
    block = int(tx["blockNumber"], 16)
    ts = None
    taken, victims = [], set()
    for t in trs:
        v = t["from"]
        if (t["amount"] <= 0 or v in (sender, to, hc.ZERO) or v in listed or t["to"] not in side):
            continue
        if not hc.is_eoa(v):
            continue
        if t["std"] == "erc20":
            ts = ts or int(hc.alchemy.block(block)["timestamp"], 16)
            usd = usd_value(t["token"], t["amount"], ts)
            if usd is None or usd < 1:
                continue
            taken.append({"std": "erc20", "token": t["token"], "usd": round(usd, 2)})
        else:
            if not verified(t["token"]):
                continue
            taken.append({"std": t["std"], "token": t["token"], "id": t["id"]})
        victims.add(v)
    if not taken:
        return None
    if any(t["to"] in victims and t["amount"] > 0 for t in trs):
        return None  # victim got something back: looks like a trade, not a drain
    kind = "drainer_nft" if any(t["std"] != "erc20" for t in taken) else "drainer_token"
    members = {sender} if sender in listed or to_is_drainer else set()
    members |= {t["to"] for t in trs if t["to"] in side and t["to"] not in emitters}
    if to_is_drainer:
        members.add(to)
    return {"tx_hash": h, "kind": kind, "block": block, "victims": sorted(victims), "taken": taken[:6],
            "operator": sender, "drainer_contract": to if to_is_drainer else None, "members": sorted(members)}


INFERNO = "0x0000db5c8b030ae20308ac975898e09741e70000"  # Etherscan name tag "Inferno Drainer" (via eth-labels)


def discover(listed, n_addresses, seed, used, head=0, snowball=False):
    rng = random.Random(seed)
    if snowball:  # newest activity of addresses already seen draining (operators, receivers, drainer contracts)
        pool = [json.loads(l) for l in open(POOL)]
        cands = sorted({m for c in pool for m in c["members"]} | {INFERNO})
        rng.shuffle(cands)
        cands = [INFERNO] + [c for c in cands if c != INFERNO]
    elif head:  # ScamSniffer all.json is newest-first: its head holds the 2024-2026 addresses
        cands = [a.lower() for a in json.loads((RAW / "scam-database/repo/blacklist/all.json").read_text())["address"]]
        cands = cands[:head]
    else:
        cands = sorted(listed)
        rng.shuffle(cands)
    cands = cands[:n_addresses]
    done = {json.loads(l)["tx_hash"] for l in open(POOL)} if POOL.exists() else set()
    lock = threading.Lock()
    stats = Counter()

    def work(x):
        order = "desc" if snowball else rng.choice(["asc", "desc"])
        hashes = []
        try:
            r = hc.alchemy.rpc("alchemy_getAssetTransfers", [{
                "toAddress": x, "category": ["erc20", "erc721", "erc1155"], "maxCount": "0x64",
                "excludeZeroValue": True, "order": order}])
            hashes += [t["hash"].lower() for t in r.get("transfers", []) if (t.get("from") or "").lower() != x]
        except RuntimeError:
            pass
        if not hc.is_eoa(x):  # drainer contract: operator calls into it
            hashes += [t["hash"].lower() for t in es_list("txlist", x, order, 40)
                       if (t.get("to") or "").lower() == x and t.get("isError") == "0"]
        hashes = [h for h in dict.fromkeys(hashes) if h not in used]
        rng.shuffle(hashes)
        kept = 0
        for h in hashes[:12]:
            if kept >= 4:
                break
            with lock:
                if h in done:
                    continue
            try:
                c = check(h, listed)
            except Exception as e:  # noqa: BLE001
                stats["err"] += 1
                continue
            if c is None:
                continue
            c["listed_seed"] = x
            with lock:
                if h in done:
                    continue
                done.add(h)
                hc.append(POOL, c)
            kept += 1
        stats["addr_with_hits" if kept else "addr_empty"] += 1
        return kept

    with ThreadPoolExecutor(8) as pool:
        for i, k in enumerate(pool.map(work, cands)):
            if i % 50 == 0:
                print(f"[discover] {i}/{len(cands)} addrs, pool={len(done)} {dict(stats)}", flush=True)
    print(f"[discover] pool={len(done)} {dict(stats)}", flush=True)


def clusters(pool, domains):
    parent = {}

    def find(a):
        parent.setdefault(a, a)
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a, b):
        parent[find(a)] = find(b)

    by_dom = defaultdict(list)
    for c in pool:
        ms = set(c["members"]) | {c["listed_seed"]}
        ok = sorted(m for m in ms if not verified(m))  # never link via legit (verified) contracts
        ms = ok or [c["listed_seed"]]
        for m in ms[1:]:
            union(ms[0], m)
        find(ms[0])
        for m in ok:
            for d in domains.get(m, ()):
                by_dom[d].append(m)
    for ms in by_dom.values():
        for m in ms[1:]:
            union(ms[0], m)
    return find


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--addresses", type=int, default=500)
    ap.add_argument("--target", type=int, default=220)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--skip-discover", action="store_true")
    ap.add_argument("--discover-only", action="store_true")
    ap.add_argument("--snowball", action="store_true")
    ap.add_argument("--head", type=int, default=0, help="seed from the newest N ScamSniffer addresses")
    args = ap.parse_args()
    listed, domains, src = load_lists()
    print(f"listed addresses: {len(listed)}", flush=True)
    used = hc.used_hashes()
    if POOL.exists():  # addresses already seen draining count as drainer side (snowball seeds)
        for l in open(POOL):
            for m in json.loads(l)["members"]:
                if m not in listed:
                    listed.add(m)
                    src[m] = "snowball"
    listed.add(INFERNO)
    src[INFERNO] = "eth-labels:Inferno Drainer"
    if not args.skip_discover:
        discover(listed, args.addresses, args.seed, used, args.head, args.snowball)
    if args.discover_only:
        return
    pool = [json.loads(l) for l in open(POOL)]
    pool = [c for c in pool if c["tx_hash"] not in used]
    find = clusters(pool, domains)
    for c in pool:
        c["group"] = "drainer:" + find(sorted(set(c["members"]) | {c["listed_seed"]})[0])[:12]
    inferno_root = find(INFERNO) if INFERNO in {m for c in pool for m in c["members"]} | {c["listed_seed"] for c in pool} else None
    for c in pool:
        if inferno_root and c["group"] == "drainer:" + inferno_root[:12]:
            c["group"] = "drainer:inferno:" + inferno_root[:12]
    # balanced selection: all 2024+ candidates first (<= 6 per group), then round-robin over groups
    rng = random.Random(args.seed)
    rng.shuffle(pool)
    by_key = defaultdict(list)
    for c in pool:
        by_key[c["group"]].append(c)
    order, per_group = [], Counter()
    for c in sorted(pool, key=lambda c: -c["block"]):
        if c["block"] >= 18_908_895 and per_group[c["group"]] < 6:  # >= 2024-01-01
            order.append(c)
            per_group[c["group"]] += 1
    taken_h = {c["tx_hash"] for c in order}
    groups = list(by_key)
    while groups and len(order) < args.target * 1.4:
        nxt = []
        for g in groups:
            rest = [c for c in by_key[g] if c["tx_hash"] not in taken_h]
            if rest and per_group[g] < 6:
                order.append(rest[0])
                taken_h.add(rest[0]["tx_hash"])
                per_group[g] += 1
                nxt.append(g)
        groups = nxt
    OUT.write_text("")
    kept = 0
    for c in order:
        if kept >= args.target:
            break
        h = c["tx_hash"]
        try:
            rec = hc.trace(h)
        except Exception as e:  # noqa: BLE001
            print(f"[trace err] {h}: {str(e)[:100]}")
            continue
        if not (rec and rec["ok"] and rec["matched"]):
            continue
        if any(to in c["victims"] for _, to, _ in hc.eth_value_calls(rec["trace"])):
            continue  # victim was paid in ETH: a sale, not a drain
        month = hc.month_of(c["block"])
        hc.append(OUT, {"incident": f"harm:{c['kind']}:{h[:10]}", "kind": c["kind"],
                        "source": src.get(c["listed_seed"], "scamsniffer"), "tx_hash": h, "label": 1,
                        "chain": "eth", "block": c["block"], "month": month, "victim": None, "group": c["group"],
                        "victim_wallets": c["victims"], "taken": c["taken"], "operator": c["operator"],
                        "drainer_contract": c["drainer_contract"], "listed_address": c["listed_seed"]})
        kept += 1
    rows = [json.loads(l) for l in open(OUT)]
    print("kept", len(rows), Counter(r["kind"] for r in rows), Counter(r["month"][:4] for r in rows),
          "groups", len({r["group"] for r in rows}))


if __name__ == "__main__":
    main()
