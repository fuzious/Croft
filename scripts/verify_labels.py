"""Verify labels from each tx's own trace: an exploit row must show real harm; a normal row must not look
like extraction. For incidents with several listed attack txs, the most harmful one replaces a harmless pick.

    uv run python scripts/verify_labels.py --cards data/cards_v5.jsonl
Writes data/cards_v5_clean.jsonl (dropped exploits removed, flagged normals removed) + data/label_report.jsonl.

Harm rule (exploit kept if ANY holds):
  - signer side net gain >= $1k, or largest third-party net loss >= $1k, or protected protocol net loss >= $1k
  - protected protocol lost >= 25% of a token holding (covers tokens with no USD price)
  - tokens were minted to the attacker's side, or >20% of a token's supply moved (governance/mint abuse)
  - third-party wallets lost >= $1k (approval drains)
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIN_USD = 1_000.0
MIN_SHARE = 0.25


def harm(feats: dict) -> tuple[float, float]:
    usd = max(feats.get("signer_usd", 0.0), feats.get("max_loss_usd", 0.0), -feats.get("prot_net_usd", 0.0),
              feats.get("eoa_loss_usd", 0.0), feats.get("nft_usd_to_signer", 0.0))
    share = max(feats.get("prot_drain_share", 0.0), feats.get("max_drain_share", 0.0) if feats.get("n_unpriced_gains") else 0.0)
    return usd, share


def is_harmful(feats: dict) -> bool:
    usd, share = harm(feats)
    # tokens minted to / supply-shocked by the attacker are value taken even when no USD price exists
    unpriced_theft = (feats.get("n_minted_to_signer", 0) > 0 or feats.get("n_supply_shock", 0) > 0
                      or feats.get("n_nft_from_eoa_to_signer", 0) > 0
                      or feats.get("n_nft_from_protocol_to_signer", 0) > 0)
    return usd >= MIN_USD or share >= MIN_SHARE or unpriced_theft


def looks_extractive(feats: dict) -> bool:
    """A 'normal' that shows clear attacker-style extraction from the protected protocol: flag for review."""
    return (-feats.get("prot_net_usd", 0.0) >= 50_000 and feats.get("signer_usd", 0.0) >= 50_000
            and (feats.get("target_unverified") or feats.get("creation_tx")))


def alternatives(row: dict) -> list[str]:
    src = {"eth": "exploits_all.jsonl", "bsc": "exploits_bsc.jsonl"}.get(row.get("chain", "eth"))
    if row["incident"].startswith("rekt:"):
        src = "incidents_rekt.jsonl"
    for l in open(ROOT / "data" / src):
        inc = json.loads(l)
        if inc["name"] == row["incident"]:
            return [h for h in inc["attack_txs"] if h != row["tx_hash"]]
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", required=True)
    ap.add_argument("--try-alternatives", action="store_true", help="trace other listed attack txs (ETH)")
    args = ap.parse_args()
    rows = [json.loads(l) for l in open(args.cards)]
    report, keep = [], []
    builder = None
    for r in rows:
        f = r["feats"]
        if r["label"] == 1:
            if is_harmful(f):
                keep.append(r)
                continue
            replaced = False
            if args.try_alternatives and r.get("chain", "eth") == "eth":
                import sys
                sys.path.insert(0, str(ROOT / "scripts"))
                import build_dataset as bd
                from oracle.card import CardBuilder
                builder = builder or CardBuilder.for_chain("eth")
                best = None
                for h in alternatives(r):
                    rec = bd.replay_and_store(h)
                    if not (rec and rec["ok"] and rec["matched"]):
                        continue
                    card, feats, meta = builder.build(rec, protected=r.get("protected"), category=r.get("category"))
                    if is_harmful(feats) and (best is None or harm(feats)[0] > harm(best[1])[0]):
                        best = (h, feats, card, meta)
                if best:
                    h, feats, card, meta = best
                    keep.append({**r, "tx_hash": h, "card": card, "feats": feats, "meta": meta, "replaced": r["tx_hash"]})
                    report.append({"incident": r["incident"], "action": "replaced", "old": r["tx_hash"], "new": h,
                                   "harm_usd": harm(feats)[0]})
                    replaced = True
            if not replaced:
                usd, share = harm(f)
                report.append({"incident": r["incident"], "action": "dropped_exploit", "tx": r["tx_hash"],
                               "harm_usd": round(usd, 2), "drain_share": round(share, 3),
                               "target": r["card"].get("target"), "path": r["card"].get("call_path", [])[:6]})
        else:
            if looks_extractive(f):  # flag for human review, but never silently drop a hard negative
                report.append({"incident": r["incident"], "action": "flagged_normal", "tx": r["tx_hash"],
                               "prot_net_usd": f.get("prot_net_usd"), "signer_usd": f.get("signer_usd")})
            keep.append(r)

    out = Path(args.cards).with_name(Path(args.cards).stem + "_clean.jsonl")
    out.write_text("".join(json.dumps(r) + "\n" for r in keep))
    (ROOT / "data" / "label_report.jsonl").write_text("".join(json.dumps(x) + "\n" for x in report))
    n_ex = sum(r["label"] for r in keep)
    acts = {}
    for x in report:
        acts[x["action"]] = acts.get(x["action"], 0) + 1
    print(f"kept {n_ex} exploits / {len(keep) - n_ex} normal -> {out}; actions: {acts}")
    for x in [x for x in report if x["action"] == "dropped_exploit"][:12]:
        print(f"  dropped {x['incident']}: harm ${x['harm_usd']:,.0f}, share {x['drain_share']}, target {x['target']}, "
              f"path {x['path'][:4]}")


if __name__ == "__main__":
    main()
