"""Validate the unchanged accounting check against recorded state and transactions; never train.

Run from the repository root: python -m near.intents.validate_accounting
The large research datasets are local inputs, not required by the transaction demo.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path

from near.intents.accounting import analyze_accounting

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "near/data/intents"
REPORT = ROOT / "near/intents/reports/accounting_validation.json"
SANDBOX = ("synthetic/attacks.jsonl.gz", "synthetic/benign.jsonl.gz",
           "synthetic/fixed_v0.4.3-backport.jsonl.gz",
           "v2_synthetic/train.jsonl.gz", "v2_synthetic/validation.jsonl.gz", "v2_synthetic/test.jsonl.gz")


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def rows(path):
    with gzip.open(path, "rt") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def state_truth(meta):
    """None means no measured state label; scenario purpose is not balance-state evidence."""
    value = (meta.get("outcome") or {}).get("ghost_credit")
    if value is None:
        return None
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise ValueError("ghost_credit must be a nonnegative decimal string")
    return int(value) > 0


def validate(data_dir=DATA):
    files = [data_dir / p for p in (*SANDBOX, "labelled.jsonl.gz", "normals.jsonl.gz")]
    for path in files:
        if not path.is_file():
            raise FileNotFoundError(f"Validation input missing: {path}")
    groups = {key: Counter() for key in ("sandbox_state_positive", "sandbox_other_unpatched",
                                        "sandbox_patched", "real_exploits", "historical_normals")}
    truth_counts, mismatches = Counter(), []
    seen, sources = set(), []
    for path in files:
        is_sandbox = path.relative_to(data_dir).as_posix() in SANDBOX
        source_counts, versions, run_ids, checked = Counter(), Counter(), Counter(), 0
        for tx in rows(path):
            meta = tx.get("_meta") or {}
            if path.name == "labelled.jsonl.gz" and meta.get("role") != "exploit":
                continue
            tx_hash = tx["transaction"]["hash"]
            if tx_hash in seen:
                raise ValueError(f"Duplicate transaction in validation inputs: {tx_hash}")
            seen.add(tx_hash)
            truth = state_truth(meta) if is_sandbox else None
            if is_sandbox and meta.get("verifier_version") not in ("v0.4.2", "v0.4.3-backport"):
                raise ValueError(f"Unknown sandbox verifier version: {meta.get('verifier_version')}")
            patched = is_sandbox and meta.get("verifier_version") == "v0.4.3-backport"
            if truth:
                key = "sandbox_state_positive"
            elif patched:
                key = "sandbox_patched"
            elif is_sandbox:
                key = "sandbox_other_unpatched"
            else:
                key = "real_exploits" if path.name == "labelled.jsonl.gz" else "historical_normals"
            result = analyze_accounting(tx)
            high = any(hit.get("severity") == "high" for hit in result["findings"])
            groups[key]["n"] += 1
            groups[key]["high_findings"] += high
            groups[key]["checked"] += result["status"] == "checked"
            groups[key]["inconclusive"] += result["status"] == "inconclusive"
            groups[key]["unsupported"] += result["status"] == "unsupported"
            if is_sandbox:
                versions[meta["verifier_version"]] += 1
                run_ids[meta.get("sandbox_run_id") or "not_recorded"] += 1
                truth_key = "positive" if truth else "zero" if truth is False else "not_measured"
                truth_counts[truth_key] += 1
                groups[key][f"state_{truth_key}"] += 1
                if truth is not None and high != truth:
                    mismatches.append({"tx_hash": tx_hash, "state_positive": truth, "high_finding": high})
            source_counts[key] += 1
            checked += 1
        sources.append({"path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
                        "sha256": sha(path), "rows_scored": checked, "groups": dict(source_counts),
                        "verifier_versions": dict(versions), "sandbox_run_ids": dict(run_ids)})
    return {
        "kind": "accounting_ground_truth_agreement", "completed_at": datetime.now(timezone.utc).isoformat(),
        "no_training": True,
        "source_sha256": {f"near/intents/{name}": sha(ROOT / "near/intents" / name)
                          for name in ("validate_accounting.py", "accounting.py", "features.py")},
        "inputs": sources, "groups": {key: dict(value) for key, value in groups.items()},
        "sandbox": {"n": sum(truth_counts.values()), "state_measurements": dict(truth_counts),
                    "measured_state_disagreements": mismatches,
                    "other_high_findings": groups["sandbox_other_unpatched"]["high_findings"]
                                           + groups["sandbox_patched"]["high_findings"]},
        "unique_transactions_scored": len(seen), "duplicate_transactions": 0,
        "interpretation": "Agreement with recorded ground truth and case labels, not unseen-attack accuracy.",
        "limits": [
            "Only rows with a recorded ghost_credit value have a direct measured balance-state label.",
            "Other sandbox executions include unmeasured benign flows and unsuccessful probes; they are not all independently proved state-negative.",
            "Real exploit labels come from the existing retrospective campaign; real normals are the existing sampled dataset, not independently measured opening/closing balances.",
            "Repeated scenarios share implementation and verifier builds, including patched runs; transactions are not independent attack techniques.",
            "The no-high-finding totals include unsupported or inconclusive accounting; absence of a finding never establishes safety or protocol solvency.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DATA)
    parser.add_argument("--out", type=Path, default=REPORT)
    args = parser.parse_args()
    if args.out.exists():
        raise SystemExit("Output exists; choose a fresh --out to preserve prior evidence")
    report = validate(args.data_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["groups"], indent=2))


if __name__ == "__main__":
    main()
