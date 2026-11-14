"""Execute categorized NEAR scenarios with disjoint method/mode and actor partitions.

Uses the existing local sandbox and WASMs; these are controlled experiments, never
mainnet attacks. Run with --help for the output and sample-count options.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import random
import time
from collections import Counter
from pathlib import Path

from near.intents.synthetic import scenarios as sc
from near.intents.synthetic.generate import record, warm_up
from near.intents.synthetic.sandbox import Account, Chain, Node, Rpc, default_binary
from near.intents.synthetic.world import build_world, wasm_paths

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT = ROOT / "near/data/intents/v2_synthetic"
REPORT = ROOT / "near/intents/reports/synthetic_families_v2.json"
VERSION = "v0.4.2"
SPLITS = ("train", "validation", "test")
TEMPLATES = {
    "callback_accounting": ("ReturnValue", "ReturnValues", "MaliciousRefund"),
    "access_control": ("mt_resolve_deposit", "ft_resolve_deposit", "nft_resolve_deposit"),
    "token_spoofing": ("ft_on_transfer", "mt_on_transfer", "mt_on_transfer_notify_overflow"),
    "resource_exhaustion": ("Panic", "ReturnBytes", "LargeReturn"),
}
BENIGN_MODES = ("AcceptAll", "RefundAll", "ReturnValues")
PROTOCOL = {
    "source": "sandbox",
    "version": VERSION,
    "templates": TEMPLATES,
    "split_order": SPLITS,
    "selection": "Templates fixed before execution; never selected by detector output.",
    "partitions": "Disjoint receiver-mode or called-method templates and actor/token namespaces; seeds are fixed.",
    "labels": "1 means a purpose-controlled attack attempt; exploit role requires measured positive ghost_credit. "
              "0 means a benign-purpose control, including ordinary failed calls. A failed call alone does not establish malicious intent.",
    "controls": "Family-matched normal/refund flows, not exact counterfactual pairs; additional insufficient-funds and low-gas failures.",
    "unavailable_families": {
        "async_reentrancy": "No verified interleaved callback/state race scenario; refund defects alone do not prove reentrancy.",
        "replay_signature": "Requires signed-message/nonce state and a verified replay exploit.",
        "oracle_price": "Requires oracle observations and a protocol valuation model.",
        "arithmetic": "Requires exact contract arithmetic and before/after state.",
        "share_accounting": "Requires share supply, underlying asset state and valuation rules.",
        "bridge_validation": "Requires the bridge verification proof and source-chain state.",
    },
    "limits": "Only four observable families are exercised. Generated accuracy is not mainnet detection accuracy. "
              "Method/mode holdouts share contract and scenario infrastructure, so they are not independent implementations.",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TemplateRandom(random.Random):
    """Restrict semantic mode/method choices while leaving amounts and batch sizes random."""
    def __init__(self, seed: int, family: str, template: str, benign: bool = False):
        super().__init__(seed)
        self.family, self.template, self.benign = family, template, benign

    def choice(self, seq):
        values = list(seq)
        if self.benign and values == ["AcceptAll", "AcceptAll", "RefundAll", "ReturnValues", "ReturnValue0"]:
            return self.template
        choices = {
            "callback_accounting": ["MaliciousRefund", "ReturnValue", "ReturnValues"],
            "access_control": sc.PRIVATE_METHODS,
            "token_spoofing": ["ft_on_transfer", "mt_on_transfer", "mt_on_transfer_notify_overflow"],
            "resource_exhaustion": ["Panic", "LargeReturn", "ReturnBytes", "ReturnValuesWrongLen"],
        }
        if not self.benign and values == choices[self.family]:
            return self.template
        return super().choice(seq)


class OverflowRandom(random.Random):
    def __init__(self, seed: int, order: str):
        super().__init__(seed)
        self.order = order

    def choice(self, seq):
        if list(seq) == ["dust_first", "dust_first", "main_first", "interleaved"]:
            return self.order
        return super().choice(seq)


def decorate(tx: dict, *, family: str, split: str, template: str, actor_group: str,
             pair: str, benign: bool) -> dict:
    meta = tx["_meta"]
    if benign and int(meta["outcome"].get("ghost_credit", "0")) > 0:
        raise ValueError("benign control unexpectedly created ghost credit; investigate before labelling")
    meta["scenario_family"] = meta.get("attack_family") or meta.get("benign_family")
    meta.update(family=family, label=0 if benign else 1, split=split,
                template_id=f"{'benign' if benign else 'attempt'}:{family}:{template}",
                actor_group=actor_group, pair_id=pair, source="sandbox", observable=True,
                ground_truth="controlled scenario purpose; exploit only when state measurements show ghost credit")
    meta["attack_family"] = None if benign else family
    if benign:
        meta["role"] = "benign"
        meta["attack_family"] = None
    elif int(meta["outcome"].get("ghost_credit", "0")) > 0:
        meta["role"] = "exploit"
    else:
        meta["role"] = "attempt"
    return tx


def failed_control(world, actors, split_index: int, rng: random.Random):
    """Ordinary wallet errors: insufficient funds or an underfunded callback chain."""
    if split_index == 0:
        status = actors.user.call(world.usdt.account_id, "ft_transfer", {
            "receiver_id": actors.user2.account_id, "amount": str(10**29)}, deposit=1, gas_tgas=30)
        template = "insufficient_ft_balance"
    elif split_index == 1:
        status = actors.user.call(world.omni.account_id, "mt_transfer_call", {
            "receiver_id": world.intents_id, "token_id": actors.main_token,
            "amount": str(10**35), "msg": ""}, deposit=1, gas_tgas=100)
        template = "insufficient_mt_balance"
    else:
        amount = str(rng.randint(1, 9) * 10**18)
        status = actors.user.call(world.omni.account_id, "mt_transfer_call", {
            "receiver_id": world.intents_id, "token_id": actors.main_token,
            "amount": amount, "msg": actors.user.account_id}, deposit=1, gas_tgas=10)
        template = "wallet_low_gas"
    return sc.Result(status, "benign", template, {}, {"failures": sc.receipt_failures(status)}, "benign")


def audit_partitions(rows):
    hashes, templates, actors, signers = set(), {}, {}, {}
    for tx in rows:
        meta = tx["_meta"]
        h = tx["transaction"]["hash"]
        if h in hashes:
            raise ValueError("duplicate transaction hash")
        hashes.add(h)
        for key, seen in (("template_id", templates), ("actor_group", actors)):
            value = meta[key]
            if value in seen and seen[value] != meta["split"]:
                raise ValueError(f"{key} crosses partitions")
            seen[value] = meta["split"]
        signer = tx["transaction"].get("signer_id")
        if signer and signer != "intents.near":
            if signer in signers and signers[signer] != meta["split"]:
                raise ValueError("signer account crosses partitions")
            signers[signer] = meta["split"]
    return {"transactions": len(hashes), "templates": len(templates), "actor_groups": len(actors),
            "signer_accounts": len(signers)}


def canonicalize_metadata(out: Path, run_id: str):
    """Normalize the family join without changing any executed transaction evidence."""
    audit = {}
    for split in SPLITS:
        path = out / f"{split}.jsonl.gz"
        with gzip.open(path, "rt") as f:
            rows = [json.loads(line) for line in f]
        evidence = lambda: hashlib.sha256(json.dumps(
            [{k: v for k, v in row.items() if k != "_meta"} for row in rows], sort_keys=True).encode()).hexdigest()
        before, before_evidence = digest(path), evidence()
        for tx in rows:
            meta = tx["_meta"]
            meta.setdefault("scenario_family", meta.get("attack_family") or meta.get("benign_family"))
            meta["attack_family"] = meta["family"] if meta["label"] else None
            meta.setdefault("sandbox_run_id", run_id)
        assert evidence() == before_evidence
        temporary = path.with_suffix(".tmp")
        with gzip.open(temporary, "wt") as f:
            for tx in rows:
                f.write(json.dumps(tx, separators=(",", ":")) + "\n")
        temporary.replace(path)
        audit[split] = {"before_sha256": before, "after_sha256": digest(path),
                        "unchanged_transaction_evidence_sha256": before_evidence}
    return audit


def supplement(out: Path, report_path: Path, seed: int):
    report = json.loads(report_path.read_text())
    if report.get("status") != "complete" or "supplement" in report:
        raise SystemExit("supplement requires a completed base run without an existing supplement")
    orders = ("dust_first", "main_first", "interleaved")
    report["supplement"] = {"status": "declared_before_execution", "rows_per_split": 6, "seed": seed,
        "orders_by_split": dict(zip(SPLITS, orders)), "generator": "attack_notify_log_overflow",
        "selection": "Exactly six draws per split, no retries or selection by detector output. "
                     "Exploit role only when measured ghost_credit >0; retain unsuccessful attempts.",
        "script_sha256": digest(Path(__file__)),
        "limitations": "Ordering-template holdouts share one exploited mechanism and implementation. "
                       "The original family-associated benign controls are not exact large-batch counterfactuals."}
    report["metadata_normalization"] = canonicalize_metadata(out, f"families-v2-base-{report['seed']}")
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    started = time.monotonic()
    node = Node(default_binary(), out / "supplement_home").start()
    counts = Counter()
    try:
        chain = Chain(Rpc(node.rpc_url))
        root_id, root_key = node.root_key()
        world = build_world(chain, Account(chain, root_id, root_key), VERSION)
        for index, (split, order) in enumerate(zip(SPLITS, orders)):
            actors = sc.make_actors(world, 200 + index, random.Random(seed + index))
            actor_group = f"families-v2-supplement-{seed}-{split}"
            with gzip.open(out / f"{split}.jsonl.gz", "at") as f:
                for i in range(6):
                    result = sc.attack_notify_log_overflow(world, actors,
                                                          OverflowRandom(seed + 1000 * index + i, order))
                    tx = decorate(record(chain, result, VERSION, 200 + index), family="callback_accounting",
                                  split=split, template=f"log_overflow:{order}", actor_group=actor_group,
                                  pair=f"{split}:overflow:{i}", benign=False)
                    tx["_meta"]["sandbox_run_id"] = f"families-v2-supplement-{seed}"
                    f.write(json.dumps(tx, separators=(",", ":")) + "\n")
                    counts[f"{split}|{tx['_meta']['role']}"] += 1
            print(f"supplement {split}: six executed log-overflow scenarios", flush=True)
    finally:
        node.stop()
    rows = []
    for split in SPLITS:
        with gzip.open(out / f"{split}.jsonl.gz", "rt") as f:
            rows.extend(json.loads(line) for line in f)
    report["supplement"].update(status="complete", counts=dict(counts),
                               duration_seconds=round(time.monotonic() - started, 2))
    report["partition_audit"] = audit_partitions(rows)
    report["counts"] = dict(sorted(Counter(f"{r['_meta']['split']}|{r['_meta']['family']}|{r['_meta']['role']}"
                                           for r in rows).items()))
    report["base_failed_receipt_rows"] = report["failed_receipt_rows"]
    report["failed_receipt_rows"] = dict(Counter(f"{r['_meta']['split']}|{r['_meta']['label']}" for r in rows
                                                 if r["_meta"]["outcome"].get("failures")))
    report["total_execution_seconds"] = round(report["duration_seconds"] + report["supplement"]["duration_seconds"], 2)
    report["files"] = {split: {"path": str(out / f"{split}.jsonl.gz"),
                               "sha256": digest(out / f"{split}.jsonl.gz")} for split in SPLITS}
    report["distributed_script_sha256"] = digest(Path(__file__))
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return report


def run(out: Path, report_path: Path, pairs: int, seed: int):
    if report_path.exists() or out.exists():
        raise SystemExit("experiment output exists; choose a fresh --out and --report")
    paths = wasm_paths(VERSION)
    for path in [default_binary(), *paths.values()]:
        if not path.is_file():
            raise SystemExit(f"Missing sandbox input: {path}; configure NEAR_SANDBOX_BIN_PATH, INTENTS_SYN_WASM_DIR and INTENTS_V042_DIR")
    out.mkdir(parents=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {"status": "declared_before_execution", "protocol": PROTOCOL, "pairs_per_family_per_split": pairs,
              "seed": seed, "script_sha256": digest(Path(__file__)),
              "inputs_sha256": {str(p): digest(p) for p in [default_binary(), *paths.values(),
                                  Path(sc.__file__), Path(__file__).with_name("generate.py")]}}
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    start = time.monotonic()
    rows, counts, failed = [], Counter(), Counter()
    node = Node(default_binary(), out / "sandbox_home").start()
    try:
        chain = Chain(Rpc(node.rpc_url))
        root_id, root_key = node.root_key()
        world = build_world(chain, Account(chain, root_id, root_key), VERSION)
        attack_fns = {"callback_accounting": sc.attack_notify_overask,
                      "access_control": sc.attack_direct_private_call,
                      "token_spoofing": sc.attack_token_spoof,
                      "resource_exhaustion": sc.attack_notify_receiver_failure}
        for split_index, split in enumerate(SPLITS):
            actor_group = f"families-v2-{seed}-{split}"
            actors = sc.make_actors(world, 100 + split_index, random.Random(seed + split_index))
            warm_up(world, actors)
            split_rows = []
            for family_index, (family, templates) in enumerate(TEMPLATES.items()):
                template = templates[split_index]
                for i in range(pairs):
                    row_seed = seed + split_index * 10000 + family_index * 1000 + i
                    pair = f"{split}:{family}:{i}"
                    for benign in (False, True):
                        mode = BENIGN_MODES[split_index] if benign else template
                        rng = TemplateRandom(row_seed, family, mode, benign)
                        result = (sc.benign_mt_deposit_notify(world, actors, rng) if benign else
                                  attack_fns[family](world, actors, rng))
                        tx = decorate(record(chain, result, VERSION, split_index), family=family,
                                      split=split, template=mode, actor_group=actor_group, pair=pair, benign=benign)
                        tx["_meta"]["sandbox_run_id"] = f"families-v2-base-{seed}"
                        split_rows.append(tx)
            for i in range(max(2, pairs // 2)):
                result = failed_control(world, actors, split_index, random.Random(seed + i))
                tx = decorate(record(chain, result, VERSION, split_index), family="benign_failure",
                              split=split, template=result.family, actor_group=actor_group,
                              pair=f"{split}:failed:{i}", benign=True)
                tx["_meta"]["sandbox_run_id"] = f"families-v2-base-{seed}"
                split_rows.append(tx)
            destination = out / f"{split}.jsonl.gz"
            with gzip.open(destination, "wt") as f:
                for tx in split_rows:
                    f.write(json.dumps(tx, separators=(",", ":")) + "\n")
                    meta = tx["_meta"]
                    counts[f"{split}|{meta['family']}|{meta['role']}"] += 1
                    if meta["outcome"].get("failures"):
                        failed[f"{split}|{meta['label']}"] += 1
            rows.extend(split_rows)
            print(f"{split}: {len(split_rows)} sandbox transactions -> {destination}", flush=True)
    finally:
        node.stop()
    report.update(status="complete", counts=dict(sorted(counts.items())), failed_receipt_rows=dict(failed),
                  partition_audit=audit_partitions(rows), duration_seconds=round(time.monotonic() - start, 2),
                  files={split: {"path": str(out / f"{split}.jsonl.gz"),
                                 "sha256": digest(out / f"{split}.jsonl.gz")} for split in SPLITS})
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--pairs", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20261114)
    parser.add_argument("--supplement", action="store_true", help="Append a predeclared 18-case executed log-overflow set")
    args = parser.parse_args()
    if not 1 <= args.pairs <= 100:
        parser.error("--pairs must be between 1 and 100")
    result = supplement(args.out, args.report, args.seed) if args.supplement else run(args.out, args.report, args.pairs, args.seed)
    print(json.dumps(result["partition_audit"]))


if __name__ == "__main__":
    main()
