"""Score the sealed test set ONCE with the frozen model and its frozen threshold.

    uv run python scripts/eval_frozen.py
"""
import json
import pickle
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]


def src(r):
    if r["label"]:
        return f"EXPLOIT ({r.get('chain', 'eth')})"
    i = r["incident"]
    return "normal: " + (r.get("source") if i.startswith("test:") else f"held-out victim normal ({r.get('chain', 'eth')})")


def main():
    frozen = pickle.loads((ROOT / "models" / "frozen_v6.pkl").read_bytes())
    rows = [json.loads(l) for l in open(ROOT / "data" / "testset_cards.jsonl")]
    train = set(json.loads((ROOT / "models" / "train_tx_hashes.json").read_text()))
    assert not train & {r["tx_hash"] for r in rows}, "test set overlaps training"
    X = np.array([[float(r["feats"].get(k, 0.0)) for k in frozen["keys"]] for r in rows])
    p = frozen["model"].predict_proba(X)[:, 1]
    flag = p >= frozen["threshold"]
    y = np.array([r["label"] for r in rows])

    tp, fp = int((flag & (y == 1)).sum()), int((flag & (y == 0)).sum())
    fn, tn = int((~flag & (y == 1)).sum()), int((~flag & (y == 0)).sum())
    print(f"SEALED TEST: {len(rows)} txs, {int(y.sum())} exploits, {int((y == 0).sum())} normal; "
          f"threshold {frozen['threshold']:.3f} (frozen)")
    print(f"  exploits caught: {tp}/{tp + fn} = {tp / (tp + fn):.1%}")
    print(f"  false alarms:    {fp}/{fp + tn} normals = {fp / (fp + tn):.2%}")
    print(f"  precision:       {tp / max(1, tp + fp):.1%}")
    by = defaultdict(lambda: [0, 0])
    for r, f in zip(rows, flag):
        by[src(r)][0] += int(f)
        by[src(r)][1] += 1
    print("  by group (flagged / total):")
    for k in sorted(by):
        print(f"    {k:48s} {by[k][0]:3d}/{by[k][1]:3d}")
    out = []
    for r, pi, f in zip(rows, p, flag):
        if bool(f) != bool(r["label"]):
            out.append({"kind": "FP" if f else "FN", "p": round(float(pi), 3), "incident": r["incident"],
                        "tx": r["tx_hash"], "source": src(r), "category": r.get("category"),
                        "target": r["card"].get("target"), "signer_side_net": r["card"].get("signer_side_net"),
                        "protected": r["card"].get("protected_protocol", {}).get("net_change")})
    (ROOT / "runs" / "sealed_test_errors.jsonl").write_text("".join(json.dumps(o) + "\n" for o in out))
    print(f"  errors written to runs/sealed_test_errors.jsonl ({len(out)})")


if __name__ == "__main__":
    main()
