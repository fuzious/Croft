"""Laya on fact cards: zero-shot, or fine-tuned with incident-grouped k-fold CV (same folds as the baseline).

    uv run python scripts/eval_laya.py --cards data/cards_v1.jsonl --mode zeroshot
    uv run python scripts/eval_laya.py --cards data/cards_v1.jsonl --mode finetune --epochs 8
"""
import argparse
import json
import os
import shutil
import time
from pathlib import Path

# Cap the MPS allocator below physical RAM (default high watermark is 1.7x the ~28 GiB recommended
# working set, i.e. > 36 GiB): past it training silently swaps (micro-batch 8 hit 37 GiB, 140 s/step).
# With the cap an oversized batch fails fast with an MPS OOM instead of thrashing. Must be set before torch loads.
os.environ.setdefault("PYTORCH_MPS_HIGH_WATERMARK_RATIO", "0.8")
os.environ.setdefault("PYTORCH_MPS_LOW_WATERMARK_RATIO", "0.6")

import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupKFold

import laya
from laya.train import TrainConfig, finetune

ROOT = Path(__file__).resolve().parents[1]
BASE = "convaiinnovations/laya"
SUBFOLDER = "typed-decisions"

VERDICT = {
    "type": "choice",
    "instructions": "This is a simulated Ethereum transaction. Is it an exploit/attack that steals funds from a "
                    "protocol or its users, or a normal transaction?",
    "criteria": {
        "normal": "Ordinary use of the protocol: trades, deposits, withdrawals, claims, admin or keeper actions.",
        "exploit": "An attack: the signer's side extracts value from a protocol or its users through a bug, "
                   "price manipulation, missing access control, or similar.",
    },
}
QUESTIONS = {"verdict": VERDICT}


def folds(groups, k, seed=0):
    rng = np.random.RandomState(seed)
    perm = {g: i for i, g in enumerate(rng.permutation(np.unique(groups)))}
    g = np.array([perm[x] for x in groups])
    return list(GroupKFold(k).split(np.zeros(len(g)), None, g))


def p_exploit(agent, card) -> float:
    ans = agent.system_one(card, QUESTIONS)["answers"]["verdict"]
    return float(ans["probabilities"]["exploit"])


def report(name, y, p, thr=0.5):
    pred = (p >= thr).astype(int)
    line = (f"{name:28s} P={precision_score(y, pred, zero_division=0):.3f} R={recall_score(y, pred):.3f} "
            f"F1={f1_score(y, pred):.3f} AUC={roc_auc_score(y, p):.3f}  (n={len(y)}, thr={thr})")
    print(line, flush=True)
    return line


def token_stats(agent, rows):
    n = [len(agent.tok(json.dumps(r["card"], ensure_ascii=False))["input_ids"]) for r in rows]
    print(f"card tokens: median {int(np.median(n))}, p95 {int(np.percentile(n, 95))}, max {max(n)} "
          f"(max_len {agent.cfg.get('max_len')})", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cards", default="data/cards_v1.jsonl")
    ap.add_argument("--mode", choices=["zeroshot", "finetune"], default="zeroshot")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--max-len", type=int, default=None)
    ap.add_argument("--tag", default=None)
    ap.add_argument("--chain", default=None)
    ap.add_argument("--loss", default="soft-ce")
    ap.add_argument("--lr", type=float, default=1e-5)
    ap.add_argument("--only-fold", type=int, default=None)
    ap.add_argument("--save-final", default=None, help="after CV, train on all rows and keep the checkpoint here")
    ap.add_argument("--final-only", action="store_true", help="skip CV; only train/save the final model")
    ap.add_argument("--merge", action="store_true", help="merge per-fold prediction files and report")
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.cards)]
    if args.chain:
        rows = [r for r in rows if r.get("chain", "eth") == args.chain]
    y = np.array([r["label"] for r in rows])
    groups = np.array([r["incident"] for r in rows])
    tag = args.tag or f"{Path(args.cards).stem}_{args.mode}"
    out_dir = ROOT / "runs" / tag
    out_dir.mkdir(parents=True, exist_ok=True)
    probs = np.zeros(len(rows))

    if args.mode == "zeroshot":
        agent = laya.load(BASE, subfolder=SUBFOLDER, device="mps")
        token_stats(agent, rows)
        for i, r in enumerate(rows):
            probs[i] = p_exploit(agent, r["card"])
    else:
        from huggingface_hub import snapshot_download
        base_dir = str(Path(snapshot_download(BASE, allow_patterns=[f"{SUBFOLDER}/*"])) / SUBFOLDER)
        for fi, (tr, te) in enumerate(folds(groups, args.folds)):
            if args.final_only or (args.only_fold is not None and fi != args.only_fold):
                continue
            t0 = time.time()
            train_path = out_dir / f"fold{fi}_train.jsonl"
            with train_path.open("w") as fh:
                for i in tr:
                    fh.write(json.dumps({"state": rows[i]["card"], "questions": QUESTIONS,
                                         "expected": {"verdict": "exploit" if y[i] else "normal"}}) + "\n")
            ckpt = out_dir / f"fold{fi}_ckpt"
            # micro_batch 2 x accum 8 (same effective batch 16): fits in ~15 GiB fp32 without swapping
            cfg = TrainConfig(epochs=args.epochs, micro_batch=2, grad_accum=8, shuffle_options=("choice",),
                              calib_frac=0.15, log_every=40, max_len=args.max_len, loss=args.loss,
                              encoder_lr=args.lr, head_lr=args.lr * 4)
            summary = finetune(str(train_path), base_dir, str(ckpt), cfg, device="mps")
            agent = laya.load(str(ckpt), device="mps")
            for i in te:
                probs[i] = p_exploit(agent, rows[i]["card"])
            del agent
            shutil.rmtree(ckpt, ignore_errors=True)
            fold_line = report(f"fold {fi}", y[te], probs[te]) if len(set(y[te])) > 1 else ""
            with (out_dir / f"predictions_fold{fi}.jsonl").open("w") as fh:
                for i in te:
                    fh.write(json.dumps({"tx_hash": rows[i]["tx_hash"], "incident": rows[i]["incident"],
                                         "label": int(y[i]), "p_exploit": float(probs[i])}) + "\n")
            print(f"fold {fi} done in {time.time() - t0:.0f}s", flush=True)

    if args.save_final and args.mode == "finetune":
        final_path = out_dir / "final_train.jsonl"
        with final_path.open("w") as fh:
            for i in range(len(rows)):
                fh.write(json.dumps({"state": rows[i]["card"], "questions": QUESTIONS,
                                     "expected": {"verdict": "exploit" if y[i] else "normal"}}) + "\n")
        cfg = TrainConfig(epochs=args.epochs, micro_batch=2, grad_accum=8, shuffle_options=("choice",),
                          calib_frac=0.15, log_every=40, max_len=args.max_len, loss=args.loss,
                          encoder_lr=args.lr, head_lr=args.lr * 4)
        finetune(str(final_path), base_dir, args.save_final, cfg, device="mps")
        print(f"final model saved to {args.save_final}", flush=True)

    if (args.only_fold is not None or args.final_only) and not args.merge:
        return
    if args.merge:
        merged = {}
        for f in sorted(out_dir.glob("predictions_fold*.jsonl")):
            for l in open(f):
                d = json.loads(l)
                merged[d["tx_hash"]] = d["p_exploit"]
        probs = np.array([merged[r["tx_hash"]] for r in rows])

    with (out_dir / "predictions.jsonl").open("w") as fh:
        for r, p in zip(rows, probs):
            fh.write(json.dumps({"tx_hash": r["tx_hash"], "incident": r["incident"], "label": r["label"],
                                 "p_exploit": p}) + "\n")
    line = report(f"laya {args.mode}", y, probs)
    for thr in (0.3, 0.7):
        report(f"laya {args.mode}", y, probs, thr)
    (out_dir / "metrics.txt").write_text(line + "\n")


if __name__ == "__main__":
    main()
