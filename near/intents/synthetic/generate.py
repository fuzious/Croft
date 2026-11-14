"""Generate labelled sandbox transactions for NEAR Intents in the FastNEAR record shape.

Run from the repo root, for example:

    .venv/bin/python -m near.intents.synthetic.generate --version v0.4.2 --attacks 600 --benign 600
    .venv/bin/python -m near.intents.synthetic.generate --version v0.4.3-backport --attacks 150 --benign 100 \
        --attack-families notify_refund_log_overflow,notify_refund_overask

Output (gzip JSONL, one FastNEAR-shaped transaction per line with `_meta`):
- v0.4.2: `near/data/intents/synthetic/attacks.jsonl.gz` and `benign.jsonl.gz`;
- any other verifier version: `near/data/intents/synthetic/fixed_<version>.jsonl.gz`;
- `summary_<version>.json`: counts per family and role.
"""

from __future__ import annotations

import argparse
import collections
import gzip
import json
import random
import shutil
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from near.intents.synthetic import scenarios
from near.intents.synthetic.fastnear_shape import to_fastnear
from near.intents.synthetic.sandbox import NEAR, SANDBOX_VERSION, Account, Chain, Node, Rpc, default_binary
from near.intents.synthetic.world import VERIFIER_WASMS, build_world

DEFAULT_OUT = Path("near/data/intents/synthetic")
DEFAULT_WORK = DEFAULT_OUT / "runs"


def record(chain: Chain, res: scenarios.Result, version: str, worker: int) -> dict:
    st = res.status
    hashes = {st["transaction_outcome"]["block_hash"]} | {ro["block_hash"] for ro in st["receipts_outcome"]}
    blocks = {}
    for h in hashes:
        hdr = chain.block(h)
        blocks[h] = {"height": hdr["height"], "timestamp": int(hdr["timestamp"])}
    tx = to_fastnear(st, blocks)
    tx["_meta"] = {
        "source": "sandbox",
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "label": res.label,
        "role": res.role,
        "campaign": f"sandbox:{res.family}",
        "attack_family": res.family if res.label == "attack" else None,
        "benign_family": res.family if res.label == "benign" else None,
        "variant": res.variant,
        "outcome": res.outcome,
        "verifier_version": version,
        "near_sandbox": SANDBOX_VERSION,
        "worker": worker,
        "data_receipts": "reconstructed from output_data_receivers; receipt_id is a stand-in",
    }
    return tx


class Writer:
    def __init__(self, paths: dict[str, Path], append: bool = False):
        # appending adds a new gzip member; readers of concatenated gzip members see one stream
        self._files = {k: gzip.open(p, "at" if append else "wt") for k, p in paths.items()}
        self._lock = threading.Lock()
        self.counts = collections.Counter()

    def write(self, kind: str, tx: dict) -> None:
        line = json.dumps(tx, separators=(",", ":"))
        with self._lock:
            self._files[kind].write(line + "\n")
            m = tx["_meta"]
            self.counts[(m["label"], m["campaign"], m["role"])] += 1

    def close(self) -> None:
        for f in self._files.values():
            f.close()


def _pick(table: dict, rng: random.Random, allowed: list[str] | None):
    names = [n for n in table if allowed is None or n in allowed]
    weights = [table[n][1] for n in names]
    name = rng.choices(names, weights)[0]
    return name, table[name][0]


def warm_up(world, a: scenarios.Actors) -> None:
    """Untracked setup: the user holds balances inside intents.near for withdrawals, transfers and intents."""
    a.user.call(world.usdt.account_id, "ft_transfer_call",
                {"receiver_id": world.intents_id, "amount": str(10**26), "msg": ""}, deposit=1, gas_tgas=100)
    a.user.call(world.omni.account_id, "mt_batch_transfer_call",
                {"receiver_id": world.intents_id, "token_ids": a.user_tokens,
                 "amounts": [str(10**28)] * len(a.user_tokens), "msg": ""}, deposit=1, gas_tgas=300)


def run(version: str, n_attacks: int, n_benign: int, workers: int, seed: int, out_dir: Path, work_dir: Path,
        attack_families: list[str] | None, benign_families: list[str] | None, append: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    home = work_dir / f"home-{version}"
    shutil.rmtree(home, ignore_errors=True)
    node = Node(default_binary(), home).start()
    if version == "v0.4.2":
        paths = {"attack": out_dir / "attacks.jsonl.gz", "benign": out_dir / "benign.jsonl.gz"}
    else:
        p = out_dir / f"fixed_{version}.jsonl.gz"
        paths = {"attack": p, "benign": p}
    writer = Writer({"attack": paths["attack"]} if paths["attack"] == paths["benign"] else paths, append)
    if paths["attack"] == paths["benign"]:
        writer._files["benign"] = writer._files["attack"]
    errors = collections.Counter()
    error_examples = {}
    t0 = time.time()
    try:
        chain = Chain(Rpc(node.rpc_url))
        root_id, root_key = node.root_key()
        root = Account(chain, root_id, root_key)
        world = build_world(chain, root, version)
        relayers = [world.new_implicit(f"relayer{i}", 100 * NEAR) for i in range(workers)]

        def worker_main(w: int) -> None:
            rng = random.Random(seed * 1000 + w)
            a = scenarios.make_actors(world, w, rng)
            warm_up(world, a)
            n_a = n_attacks // workers + (1 if w < n_attacks % workers else 0)
            n_b = n_benign // workers + (1 if w < n_benign % workers else 0)
            plan = ["attack"] * n_a + ["benign"] * n_b
            rng.shuffle(plan)
            for kind in plan:
                table, allowed = ((scenarios.ATTACKS, attack_families) if kind == "attack"
                                  else (scenarios.BENIGN, benign_families))
                name, fn = _pick(table, rng, allowed)
                try:
                    if name == "execute_intents":
                        res = fn(world, a, rng, relayers[w])
                    else:
                        res = fn(world, a, rng)
                    writer.write(kind, record(chain, res, version, w))
                except Exception as e:  # keep generating; failures are counted and reported
                    errors[name] += 1
                    error_examples.setdefault(name, "".join(traceback.format_exception_only(e))[:800])

        with ThreadPoolExecutor(workers) as pool:
            for f in [pool.submit(worker_main, w) for w in range(workers)]:
                f.result()
    finally:
        writer.close()
        node.stop()

    summary = {
        "verifier_version": version,
        "near_sandbox": SANDBOX_VERSION,
        "seconds": round(time.time() - t0),
        "counts": {f"{lbl}|{camp}|{role}": n for (lbl, camp, role), n in sorted(writer.counts.items())},
        "errors": dict(errors),
        "error_examples": error_examples,
        "files": {k: str(p) for k, p in paths.items()},
    }
    summary_path = out_dir / f"summary_{version}.json"
    if append and summary_path.exists():
        previous = json.loads(summary_path.read_text())
        summary["previous_runs"] = previous.pop("previous_runs", []) + [previous]
    summary_path.write_text(json.dumps(summary, indent=2))
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", default="v0.4.2", choices=sorted(VERIFIER_WASMS))
    ap.add_argument("--attacks", type=int, default=600)
    ap.add_argument("--benign", type=int, default=600)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--work", type=Path, default=DEFAULT_WORK)
    ap.add_argument("--attack-families", default=None, help="comma-separated subset of scenarios.ATTACKS")
    ap.add_argument("--benign-families", default=None, help="comma-separated subset of scenarios.BENIGN")
    ap.add_argument("--append", action="store_true", help="append to the output files instead of replacing them")
    args = ap.parse_args(argv)
    split = (lambda s: s.split(",") if s else None)
    summary = run(args.version, args.attacks, args.benign, args.workers, args.seed, args.out, args.work,
                  split(args.attack_families), split(args.benign_families), args.append)
    json.dump(summary, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
