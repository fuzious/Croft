"""Read-only: per-transaction mechanism labels for the 437 real attack-labelled Intents transactions.

Mechanism = entry method + the contract's own rejection reason; detection = served rules + accounting (no model).
Usage: python -m near.intents.audit.mechanism_table --out <out.json>
"""
import argparse
import gzip
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from near.intents import features as ft
from near.intents.accounting import analyze_accounting

DATA = Path(__file__).resolve().parents[3] / "near/data/intents"
SEV = {"high": 3, "medium": 2, "low": 1}
SIG = re.compile(r"invalid signature|public key .{0,90}doesn't exist for account|nonce was already used|deadline|"
                 r"expired|wrong recipient", re.I)
BAL = re.compile(r"insufficient balance or overflow|invariant violated|invalid intent|zero amount", re.I)
MAL = re.compile(r"deserializ|JSON:|doesn't accept deposit", re.I)
GROUPS = (("Receipt-visible mechanisms M1-M5", ("M1", "M2", "M3", "M4", "M5")),
          ("Signed-intent probes M6", ("M6",)), ("Other campaign calls M7", ("M7",)))


def mechanism(row, tx):
    methods = row["methods"] or ["?"]
    m = methods[0]
    camp = row["incident"][:10]
    fails = []
    for x in tx.get("receipts", []):
        st = ((x.get("execution_outcome") or {}).get("outcome") or {}).get("status") or {}
        if isinstance(st, dict) and "Failure" in st:
            fails.append(json.dumps(st["Failure"]))
    first = fails[0] if fails else ""
    if camp == "2026-10-01":
        return "M1 notify deposit: resolve callback fails on log limit, credit kept"
    if m in ft.ON_TRANSFER:
        return "M3 direct token-hook call (*_on_transfer) by a non-token signer"
    if ft._RESOLVE_RE.search(m) or m.startswith("do_"):
        return "M4 direct private callback (*_resolve_*, do_*)"
    if ft._is_admin(m):
        return "M5 admin / role-gated method"
    if m == "execute_intents":
        if not fails:
            return "M6d signed intent accepted (no failed receipt)"
        if SIG.search(first):
            return "M6a signed intent rejected: signature / key / nonce / deadline"
        if BAL.search(first):
            return "M6b signed intent rejected: balance / invariant / invalid intent"
        if MAL.search(first):
            return "M6c signed intent rejected: malformed payload"
        return "M6e signed intent rejected: other"
    if camp == "2026-04-03" and m == "ft_transfer_call":
        return "M2 notify deposit with starved callback gas"
    return "M7 ordinary deposit / withdrawal / transfer / key call by the campaign signer"


def table(labels, labelled):
    lab = {}
    with open(labels) as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                lab[r["tx_hash"]] = r
    tab = defaultdict(lambda: Counter())
    rules_by = defaultdict(Counter)
    n = 0
    with gzip.open(labelled, "rt") as f:
        txs = [json.loads(line) for line in f]
    for tx in txs:
        row = lab.get(tx["transaction"]["hash"])
        if not row or row["role"] not in ("attempt", "exploit"):
            continue
        n += 1
        hits = ft.rule_hits(tx)
        acc = analyze_accounting(tx).get("findings", [])
        top = max([SEV[h["severity"]] for h in hits + acc], default=0)
        mech = mechanism(row, tx)
        key = (mech, row["incident"][:10])
        tab[key]["n"] += 1
        tab[key]["high"] += top >= 3
        tab[key]["medium_plus"] += top >= 2
        for h in hits:
            if SEV[h["severity"]] >= 2:
                rules_by[key][h["rule"]] += 1
    out = []
    for (mech, camp), c in sorted(tab.items()):
        out.append({"mechanism": mech, "campaign": camp, **c, "rules": dict(rules_by[(mech, camp)])})
    return {"n": n, "rows": out}


def summary(rows):
    agg = defaultdict(Counter)
    for r in rows:
        for k in ("n", "high", "medium_plus"):
            agg[r["mechanism"]][k] += r[k]
    groups = []
    for name, prefixes in GROUPS:
        c = Counter()
        for mech, counts in agg.items():
            if mech[:2] in prefixes:
                c.update(counts)
        groups.append({"group": name, "n": c["n"], "medium_plus": c["medium_plus"]})
    return agg, groups


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", default=DATA / "all_labelled_txs.jsonl")
    parser.add_argument("--labelled", default=DATA / "labelled.jsonl.gz")
    parser.add_argument("--out", required=True, type=Path, help="JSON output path; refuses to overwrite")
    args = parser.parse_args()
    result = table(args.labels, args.labelled)
    with open(args.out, "x") as f:
        json.dump(result, f, indent=1)
    print("positives", result["n"])
    for r in result["rows"]:
        print(f"{r['mechanism'][:74]:74s} {r['campaign']} n={r['n']:3d} high={r['high']:3d} "
              f"med+={r['medium_plus']:3d} {r['rules']}")
    print()
    agg, groups = summary(result["rows"])
    tot = Counter()
    for mech, c in sorted(agg.items()):
        print(f"{mech[:74]:74s} n={c['n']:3d} high={c['high']:3d} med+={c['medium_plus']:3d}")
        tot.update(c)
    print("TOTAL", dict(tot))
    for g in groups:
        print(f"{g['group']:34s} med+={g['medium_plus']}/{g['n']}")


if __name__ == "__main__":
    main()
