"""Collect and replay the labelled dataset: real exploit txs + normal txs to the same victim contracts.

For each DeFiHackLabs mainnet incident whose victim contract is verified on Etherscan:
  - exploit: the first attack tx (must replay with the same status/log count as on mainnet)
  - normal:  the most recent successful tx sent directly to the victim before the attack block,
             by someone other than the attacker (falls back to txs that moved the victim's tokens)
Replays are stored in data/replays/<hash>.json so fact cards can be rebuilt offline.

    uv run python scripts/build_dataset.py --target 100 --workers 3
"""
import argparse
import json
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from oracle.replay import Replayer
from oracle.sources import Alchemy, Drpc, Etherscan

ROOT = Path(__file__).resolve().parents[1]
REPLAYS = ROOT / "data" / "replays"
OUT = ROOT / "data" / "dataset.jsonl"
INCIDENTS = ROOT / "data" / "exploits_all.jsonl"
CHAIN = "eth"

etherscan = Etherscan()
alchemy = Alchemy()
local = threading.local()
ports = iter(range(8700, 8800))
port_lock = threading.Lock()
# Archive nodes that serve historical state; each worker forks from its own to spread the rate limits.
UPSTREAMS_BY_CHAIN = {
    "eth": [None, "https://eth.drpc.org", "https://eth-mainnet.public.blastapi.io",
            "https://mainnet.gateway.tenderly.co"],
    "bsc": [None, "https://bsc-mainnet.public.blastapi.io"],
    "base": [None],
}
UPSTREAMS = UPSTREAMS_BY_CHAIN["eth"]
PORT_BASE = 8700


def configure(chain: str):
    global CHAIN, etherscan, alchemy, UPSTREAMS, OUT, INCIDENTS, ports, PORT_BASE
    CHAIN = chain
    etherscan, alchemy = Etherscan(chain), Alchemy(chain, key=1 if chain == "base" else 0)
    UPSTREAMS = UPSTREAMS_BY_CHAIN[chain]
    if chain != "eth":
        # Base is test-only (never trained on): keep it out of the dataset*.jsonl training glob
        OUT = ROOT / "data" / (f"test2_{chain}.jsonl" if chain == "base" else f"dataset_{chain}.jsonl")
        INCIDENTS = ROOT / "data" / f"exploits_{chain}.jsonl"
        PORT_BASE = 8900 if chain == "bsc" else 9100
        ports = iter(range(PORT_BASE, PORT_BASE + 100))


def replayer() -> Replayer:
    if not hasattr(local, "rp"):
        with port_lock:
            port = next(ports)
        local.rp = Replayer(port=port, alchemy=alchemy, upstream=UPSTREAMS[(port - PORT_BASE) % len(UPSTREAMS)])
    return local.rp


_drpc: dict = {}


def trace_direct(h: str) -> dict | None:
    """Exact on-chain execution: dRPC callTracer + the real receipt logs (chains where dRPC serves traces)."""
    if CHAIN not in ("eth", "base"):
        return None
    drpc = _drpc.setdefault(CHAIN, Drpc(CHAIN))
    tx = alchemy.tx(h)
    if tx is None:
        raise LookupError(f"{h} not found")
    receipt = alchemy.receipt(h)
    try:
        trace = drpc.rpc("debug_traceTransaction", [h, {"tracer": "callTracer", "tracerConfig": {"withLog": True}}],
                         cache=False)
    except RuntimeError:
        return None
    status = int(receipt["status"], 16)
    return {"tx_hash": h, "tx": tx, "block": alchemy.block(int(tx["blockNumber"], 16)), "ok": status == 1,
            "matched": True, "orig_status": status, "trace": trace, "logs": receipt["logs"], "error": None,
            "source": "mainnet_trace"}


def replay_and_store(h: str) -> dict | None:
    path = REPLAYS / f"{h}.json"
    if path.exists():
        cached = json.loads(path.read_text())
        if cached["ok"] and cached["matched"]:
            return cached
        if cached.get("source") == "mainnet_trace" or CHAIN not in ("eth", "base"):
            return cached
    rec = trace_direct(h)
    if rec is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rec))
        return rec
    r = replayer().replay(h)
    rec = {"tx_hash": h, "tx": r.tx, "block": r.block, "ok": r.ok, "matched": r.matched,
           "orig_status": r.orig_status, "trace": r.trace, "logs": r.logs, "error": r.error}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rec))
    return rec


def pick_normal_rpc(victim: str, attack_block: int, bad: set[str], max_blocks: int = 300) -> list[str]:
    """Normal txs sent directly to the victim, found by scanning full blocks backwards from the attack
    (for chains where the explorer's account/log APIs are paywalled and getLogs ranges are capped)."""
    out = []
    for b in range(attack_block - 1, attack_block - 1 - max_blocks, -1):
        try:
            block = alchemy.rpc("eth_getBlockByNumber", [hex(b), True], cache=False)
        except RuntimeError:
            continue
        for tx in reversed(block.get("transactions", [])):
            if ((tx.get("to") or "").lower() == victim and tx["from"].lower() not in bad
                    and len(tx.get("input", "")) > 10):
                out.append(tx["hash"].lower())
        if len(out) >= 5:
            break
    return out[:5]


def pick_normal(victim: str, attack_block: int, bad: set[str]) -> list[str]:
    if CHAIN != "eth":
        return pick_normal_rpc(victim, attack_block, bad)
    candidates = []
    for t in etherscan.txlist(victim, attack_block - 1, offset=200):
        if (t.get("isError") == "0" and (t.get("to") or "").lower() == victim
                and len(t.get("input", "")) > 10 and t["from"].lower() not in bad):
            candidates.append(t["hash"].lower())
    if not candidates:  # victim is usually reached through routers: use txs that moved its tokens
        for t in etherscan.txlist(victim, attack_block - 1, offset=200, action="tokentx"):
            if t["from"].lower() not in bad and t["to"].lower() not in bad:
                candidates.append(t["hash"].lower())
    return list(dict.fromkeys(candidates))[:5]


def process(inc: dict) -> list[dict]:
    victim = inc["victim"][0]
    src = etherscan.source(victim)
    if not src["verified"]:
        return [{"incident": inc["name"], "skip": "victim not verified"}]
    attack = inc["attack_txs"][0]
    ex = replay_and_store(attack)
    if not (ex["ok"] and ex["matched"]):
        return [{"incident": inc["name"], "skip": f"exploit replay ok={ex['ok']} matched={ex['matched']}"}]
    block = int(ex["tx"]["blockNumber"], 16)
    bad = {a.lower() for a in inc.get("attacker", []) + inc.get("attack_contract", [])} | {ex["tx"]["from"].lower()}
    base = {"incident": inc["name"], "chain": CHAIN, "month": inc.get("month"), "victim": victim,
            "victim_name": src["name"]}
    rows = [{**base, "tx_hash": attack, "label": 1, "block": block}]
    for h in pick_normal(victim, block, bad):
        try:
            nr = replay_and_store(h)
        except Exception as e:  # noqa: BLE001
            continue
        if nr["ok"] and nr["matched"]:
            rows.append({**base, "tx_hash": h, "label": 0, "block": int(nr["tx"]["blockNumber"], 16)})
            break
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=100)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--chain", default="eth")
    args = ap.parse_args()
    configure(args.chain)
    incidents = [json.loads(l) for l in open(INCIDENTS)]
    incidents = [i for i in incidents if i.get("victim")]
    incidents.sort(key=lambda i: i.get("month") or "0000", reverse=True)  # newest first

    rows, skips = [], []
    OUT.write_text("")
    with ThreadPoolExecutor(args.workers) as pool:
        futs = {pool.submit(process, inc): inc for inc in incidents}
        for f in as_completed(futs):
            inc = futs[f]
            try:
                out = f.result()
            except Exception as e:  # noqa: BLE001
                skips.append({"incident": inc["name"], "skip": f"error: {str(e)[:160]}"})
                print(f"[err ] {inc['name']}: {str(e)[:160]}", flush=True)
                continue
            for r in out:
                (skips if "skip" in r else rows).append(r)
                if "skip" not in r:
                    with OUT.open("a") as fh:
                        fh.write(json.dumps(r) + "\n")
            n_ex = sum(r["label"] for r in rows)
            print(f"[{n_ex:3d} ex / {len(rows) - n_ex:3d} ok] {inc['name']}: "
                  f"{'; '.join(r.get('skip', 'label=%d' % r.get('label', -1)) for r in out)}", flush=True)

    (ROOT / "data" / f"dataset_skips{'' if CHAIN == 'eth' else '_' + CHAIN}.jsonl").write_text("".join(json.dumps(s) + "\n" for s in skips))
    n_ex = sum(r["label"] for r in rows)
    print(f"done: {n_ex} exploits, {len(rows) - n_ex} normal, {len(skips)} skipped -> {OUT}")


if __name__ == "__main__":
    main()
