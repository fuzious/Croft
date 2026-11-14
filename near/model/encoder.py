"""Fine-tuned code encoder (UniXcoder by default) that scores NEAR Rust functions vulnerable/safe, trained on MPS.

Input: a one-line header (fn attrs, #[near_bindgen], `pub`, analyzer detector hits) + the function code (comments
optionally stripped, whitespace collapsed), head+tail truncated to 512 tokens. Evaluated with near.model.eval_common:
outer GroupKFold over `group` on train_v1 (minus the split-audit drop ids); inside each outer-train split one inner
group fold is the validation set for epoch selection and the block/warn thresholds; the outer fold is scored once.
Training rows come from train_v1_small; scored rows (validation, outer test, OOF) are all of train_v1.

    uv run python -m near.model.encoder cv --model unixcoder --folds 3 --tag unixcoder_cv3   # background it
    uv run python -m near.model.encoder report --tag unixcoder_cv3
    uv run python -m near.model.encoder latency --tag unixcoder_cv3
    uv run python -m near.model.encoder final --tag unixcoder_final   # deployable checkpoint + thresholds
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import time
from multiprocessing import Pool
from pathlib import Path

import numpy as np

from near.analyzer import detect, extract_functions
from near.analyzer.detectors import strip_comments
from near.model import eval_common as ev

DATA, OUT = Path("near/data"), Path("near/models")
TRAIN, SMALL, DROP = DATA / "train_v1.jsonl", DATA / "train_v1_small.jsonl", DATA / "split_audit_v1_drop_ids.json"
REPORT = Path("near/model/reports")
MODELS = {"unixcoder": "microsoft/unixcoder-base", "modernbert": "answerdotai/ModernBERT-base",
          "codebert": "microsoft/codebert-base"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_train() -> tuple[list[dict], set[str]]:
    """train_v1 rows minus the split-audit drop ids (refuses if train_v1 changed), and the ids of train_v1_small."""
    drop = json.loads(DROP.read_text())
    if sha256(TRAIN) != drop["train_sha256"]:
        raise SystemExit(f"{TRAIN} sha256 differs from the one {DROP} was built for")
    bad = set(drop["ids"])
    rows = [r for r in map(json.loads, TRAIN.open()) if r["id"] not in bad]
    small = {json.loads(l)["id"] for l in SMALL.open()} - bad
    return rows, small


def fn_view(r: dict) -> dict:
    """The analyzer's view of a row, derived from the code text alone so every source gets the same fields."""
    fns = [f for f in extract_functions(r["code"], r.get("path") or "") if f["fn"] == r["fn"]]
    f = fns[0] if fns else {"attrs": r.get("attrs") or [], "is_public": bool(re.search(r"\bpub\s+fn\b", r["code"]))}
    return {"fn": r["fn"], "code": r["code"], "impl": r.get("impl"), "is_near_bindgen": bool(r.get("is_near_bindgen")),
            "attrs": f["attrs"], "is_public": f["is_public"], "is_payable": "payable" in f["attrs"]}


def input_text(r: dict, strip: bool = True) -> tuple[str, str]:
    """(header, body) fed to the encoder."""
    f = fn_view(r)
    hits = sorted({h["detector"] for h in detect(f)})
    head = (f"attrs: {','.join(f['attrs']) or '-'} | bindgen: {int(f['is_near_bindgen'])} | "
            f"public: {int(f['is_public'])} | hits: {','.join(hits) or '-'}")
    code = strip_comments(r["code"]) if strip else r["code"]
    body = "\n".join(x for x in (re.sub(r"[ \t]+", " ", ln).strip() for ln in code.splitlines()) if x)
    return head, body


def _inputs(args):
    return input_text(*args)


def all_inputs(rows: list[dict], strip: bool) -> list[tuple[str, str]]:
    with Pool(16) as p:
        return p.map(_inputs, [(r, strip) for r in rows], chunksize=256)


def truncate_ids(head: list[int], code: list[int], budget: int) -> list[int]:
    """Header kept whole; code cut to its head and tail so the total fits `budget`."""
    if len(head) + len(code) <= budget:
        return head + code
    room = max(0, budget - len(head))
    return head + code[:room - room // 2] + (code[-(room // 2):] if room // 2 else [])


def encode(tok, texts: list[tuple[str, str]], max_len: int) -> list[list[int]]:
    hs = tok([h for h, _ in texts], add_special_tokens=False)["input_ids"]
    bs = tok([b for _, b in texts], add_special_tokens=False)["input_ids"]
    cls, sep = tok.cls_token_id, tok.sep_token_id
    return [[cls] + truncate_ids(h + [sep], b, max_len - 2) + [sep] for h, b in zip(hs, bs)]


def fold_plan(rows: list[dict], outer: int, seed: int = ev.SEED) -> list[tuple[np.ndarray, np.ndarray, np.ndarray]]:
    """(inner-train, inner-validation, outer-test) index arrays per outer fold: outer folds as eval_common, the
    validation set is the first of eval_common's inner group folds for that outer split."""
    plan = []
    for f, (tr, te) in enumerate(ev.group_folds(rows, outer, seed)):
        itr, ival = ev.group_folds([rows[i] for i in tr], 3, seed + 1 + f)[0]
        plan.append((tr[itr], tr[ival], te))
    return plan


def batches(lengths: np.ndarray, idx, max_tokens: int, rng=None, max_batch: int = 64, step: int = 64) -> list:
    """Batches bucketed by length rounded up to `step`, a fixed size per bucket within max_tokens padded tokens
    (few distinct tensor shapes: MPS is slow on varying shapes); shuffled when rng is given."""
    idx = np.asarray(idx)
    if rng is not None:
        idx = rng.permutation(idx)
    padded = -(-lengths[idx] // step) * step
    out = []
    for L in np.unique(padded):
        b = idx[padded == L]
        size = max(1, min(max_batch, max_tokens // int(L)))
        out += [b[i:i + size] for i in range(0, len(b), size)]
    if rng is not None:
        out = [out[i] for i in rng.permutation(len(out))]
    return out


def collate(ids: list[list[int]], pad: int, device, step: int = 64):
    import torch
    n = -(-max(map(len, ids)) // step) * step
    x = torch.full((len(ids), n), pad, dtype=torch.long)
    for i, s in enumerate(ids):
        x[i, :len(s)] = torch.tensor(s)
    return x.to(device), (x != pad).long().to(device)


def predict(model, ids: list[list[int]], idx: np.ndarray, pad: int, device, max_tokens: int = 16384) -> np.ndarray:
    import torch
    lengths = np.array([len(s) for s in ids])
    out = np.zeros(len(ids))
    model.eval()
    with torch.no_grad():
        for b in batches(lengths, np.asarray(idx), max_tokens, max_batch=256):
            x, m = collate([ids[i] for i in b], pad, device)
            with torch.autocast(device.type, dtype=torch.bfloat16, enabled=device.type == "mps"):
                out[b] = torch.sigmoid(model(input_ids=x, attention_mask=m).logits.float().squeeze(-1)).cpu().numpy()
    return out[np.asarray(idx)]


def train_fold(args, rows, ids, pad, tr, val, te, fdir: Path, log) -> dict:
    """Fine-tune on tr, keep the epoch with the best inner selection score on val, score val and te."""
    import torch
    from transformers import AutoModelForSequenceClassification, get_linear_schedule_with_warmup
    torch.manual_seed(ev.SEED)
    dev = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    model = AutoModelForSequenceClassification.from_pretrained(MODELS[args.model], num_labels=1).to(dev)
    y = torch.tensor([float(rows[i]["label"]) for i in range(len(rows))])
    w = np.zeros(len(rows))
    w[tr] = ev.sample_weights([rows[i] for i in tr])
    w /= w[tr].mean()
    w = torch.tensor(w, dtype=torch.float32)
    lengths = np.array([len(s) for s in ids])
    rng = np.random.RandomState(ev.SEED)
    steps = sum(len(batches(lengths, tr, args.max_tokens, np.random.RandomState(e))) for e in range(args.epochs))
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    sched = get_linear_schedule_with_warmup(opt, int(0.06 * steps), steps)
    val_rows = [rows[i] for i in val]
    best, hist, t0, step = (-1.0, None, None, None), [], time.time(), 0
    for epoch in range(args.epochs):
        model.train()
        for b in batches(lengths, tr, args.max_tokens, rng):
            x, m = collate([ids[i] for i in b], pad, dev)
            with torch.autocast("mps", dtype=torch.bfloat16, enabled=dev.type == "mps"):
                logit = model(input_ids=x, attention_mask=m).logits.float().squeeze(-1)
            loss = torch.nn.functional.binary_cross_entropy_with_logits(logit, y[b].to(dev), reduction="none")
            loss = (loss * w[b].to(dev)).sum() / len(b)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step(); sched.step(); opt.zero_grad(set_to_none=True)
            step += 1
            if step % 200 == 0:
                log(f"    step {step}/{steps} loss {loss.item():.4f} {time.time() - t0:.0f}s")
        s_val = predict(model, ids, val, pad, dev)
        sel = ev.selection_score(val_rows, s_val)
        met = ev.metrics(val_rows, s_val)
        hist.append({"epoch": epoch + 1, "selection": sel, "val_pr_auc": met["pr_auc"],
                     "val_recall_real_noninfo_warn": met["warn"]["recall_real_noninfo"]["rate"],
                     "val_recall_mutation_warn": met["warn"]["recall_mutation"]["rate"], "seconds": time.time() - t0})
        log(f"    epoch {epoch + 1}: {hist[-1]}")
        if sel > best[0]:
            best = (sel, epoch + 1, {k: v.detach().to("cpu", copy=True) for k, v in model.state_dict().items()}, s_val)
    if best[1] != args.epochs:
        model.load_state_dict(best[2])
    s_val = best[3]
    thr = ev.thresholds_from(val_rows, s_val)
    s_te = predict(model, ids, te, pad, dev) if len(te) else np.zeros(0)
    if args.save:
        model.save_pretrained(fdir / "checkpoint")
    for name, idx, s in (("val", val, s_val), ("test", te, s_te)):
        with (fdir / f"scores_{name}.jsonl").open("w") as fh:
            for i, v in zip(idx, s):
                fh.write(json.dumps({"id": rows[i]["id"], "score": float(v)}) + "\n")
    return {"best_epoch": best[1], "history": hist, "thresholds": thr, "n_train": len(tr), "n_val": len(val),
            "n_test": len(te), "seconds": time.time() - t0}


def cv(args):
    from transformers import AutoTokenizer
    root = OUT / f"encoder_{args.tag}"
    root.mkdir(parents=True, exist_ok=True)
    logf = (root / "train.log").open("a")

    def log(msg):
        print(msg, flush=True); logf.write(msg + "\n"); logf.flush()

    rows, small = load_train()
    t = time.time()
    texts = all_inputs(rows, bool(args.strip))
    tok = AutoTokenizer.from_pretrained(MODELS[args.model])
    ids = encode(tok, texts, args.max_len)
    log(f"{args.tag}: {len(rows)} rows ({len(small)} small), inputs+tokens {time.time() - t:.0f}s, "
        f"median len {int(np.median([len(s) for s in ids]))}, truncated {sum(len(s) >= args.max_len for s in ids)}")
    config = vars(args) | {"hf_model": MODELS[args.model], "train_sha256": sha256(TRAIN), "small_sha256": sha256(SMALL)}
    (root / "config.json").write_text(json.dumps(config, indent=1))
    in_small = np.array([r["id"] in small for r in rows])
    rng = np.random.RandomState(ev.SEED)
    if args.cmd == "final":  # deployable model: 4/5 of the groups, the other 1/5 calibrates the thresholds
        tr, val = ev.group_folds(rows, 5, ev.SEED + 99)[0]
        plan, names = [(tr, val, val[:0])], ["final"]
    else:
        plan = fold_plan(rows, args.folds)
        names = [f"fold{f}" for f in range(len(plan))]
    for f, (tr, val, te) in enumerate(plan):
        if args.only_fold is not None and f != args.only_fold:
            continue
        fdir = root / names[f]
        if (fdir / "fold.json").exists():
            log(f"  fold {f} done, skipping"); continue
        fdir.mkdir(exist_ok=True)
        tr = tr[in_small[tr]]
        if args.train_frac < 1:
            tr = np.sort(rng.choice(tr, int(len(tr) * args.train_frac), replace=False))
        if args.no_test:
            te = te[:0]
        log(f"  fold {f}: train {len(tr)} val {len(val)} test {len(te)}")
        info = train_fold(args, rows, ids, tok.pad_token_id, tr, val, te, fdir, log)
        (fdir / "fold.json").write_text(json.dumps(info, indent=1))
        log(f"  fold {f} done in {info['seconds']:.0f}s: best epoch {info['best_epoch']} thresholds {info['thresholds']}")


def read_scores(path: Path) -> dict[str, float]:
    return {d["id"]: d["score"] for d in map(json.loads, path.open())}


def oof(tag: str, rows: list[dict]):
    """Pooled outer-fold scores and nested decisions (each fold's validation thresholds) over `rows`."""
    root = OUT / f"encoder_{tag}"
    pos = {r["id"]: i for i, r in enumerate(rows)}
    scores = np.full(len(rows), np.nan)
    thr_row = {lvl: np.full(len(rows), np.inf) for lvl in ev.LEVELS}
    folds = []
    for fdir in sorted(root.glob("fold[0-9]*")):
        info = json.loads((fdir / "fold.json").read_text())
        for k, v in read_scores(fdir / "scores_test.jsonl").items():
            scores[pos[k]] = v
            for lvl in ev.LEVELS:
                thr_row[lvl][pos[k]] = info["thresholds"][lvl]
        folds.append(info)
    return scores, {lvl: scores >= thr_row[lvl] for lvl in ev.LEVELS}, folds


def _row(name: str, d: dict) -> str:
    return f"| {name} | {ev.fmt_rate(d)} |"


def report(args):
    rows, _ = load_train()
    scores, dec, folds = oof(args.tag, rows)
    if np.isnan(scores).any():
        raise SystemExit(f"{int(np.isnan(scores).sum())} rows have no outer-fold score yet")
    m = ev.metrics(rows, scores, dec)
    m_pooled = ev.metrics(rows, scores)
    cfg = json.loads((OUT / f"encoder_{args.tag}" / "config.json").read_text())
    with (OUT / "encoder_oof.jsonl").open("w") as fh:
        for r, s in zip(rows, scores):
            fh.write(json.dumps({"id": r["id"], "score": float(s)}) + "\n")
    lat = OUT / f"encoder_{args.tag}" / "latency.json"
    exp = {p.parent.parent.name: json.loads(p.read_text()) for p in OUT.glob("encoder_xp_*/fold0/fold.json")}
    exp_cfg = {p.parent.name: json.loads(p.read_text()) for p in OUT.glob("encoder_*/config.json")}
    out = {"tag": args.tag, "config": cfg, "metrics_nested": m, "metrics_pooled_thresholds": m_pooled,
           "folds": folds, "latency": json.loads(lat.read_text()) if lat.exists() else None,
           "inner_val_experiments": {k: {"config": exp_cfg.get(k), "fold0": v} for k, v in exp.items()},
           "oof_sha256": sha256(OUT / "encoder_oof.jsonl")}
    REPORT.mkdir(parents=True, exist_ok=True)
    (REPORT / "encoder_cv.json").write_text(json.dumps(out, indent=1, default=float))
    L = [f"# Code encoder: nested grouped CV on train_v1 ({cfg['hf_model']}, {cfg['folds']} outer folds)", "",
         f"{m['n']} rows, {m['n_pos']} label-1. Pooled over {len(folds)} outer folds. Thresholds per fold from its "
         "inner validation fold (contract-code corpus negatives).", "",
         f"- PR-AUC {m['pr_auc']:.4f} (weighted {m['pr_auc_weighted']:.4f}), ROC-AUC {m['roc_auc']:.4f}",
         f"- ROC-AUC real label-1 vs contract corpus {m['roc_auc_real_vs_contract_corpus']:.4f}; "
         f"mutation vs contract corpus {m['roc_auc_mutation_vs_contract_corpus']:.4f}; "
         f"real label-1 vs fixed {m['roc_auc_real_vs_fixed']:.4f}",
         f"- Pair ranking (vulnerable > fixed): {ev.fmt_rate(m['pair_rank_acc'])}", "",
         "Protocol and limits:",
         f"- Rows: train_v1 minus the {DROP.name} ids (train sha256 checked); test_v1 never read. Every train_v1 row gets "
         "one outer-fold score (near/models/encoder_oof.jsonl).",
         f"- {cfg['folds']} outer folds (eval_common.group_folds, seed {ev.SEED}), not 5, for wall-clock: the encoder trains "
         "on train_v1_small rows of 2/3 of each outer-train split (~26.5k rows; the classical trainer fits ~53k), so it is "
         "at a data disadvantage. Folds differ from the classical 5-fold run.",
         "- Epoch choice (eval_common.selection_score) and thresholds come from one inner validation fold (1/3 of the "
         "outer-train groups, all its train_v1 rows), not from inner OOF over all inner folds; the validation fold is "
         "not trained on, so the outer fold still sees nested thresholds. Selection is noisy (~100 real non-info "
         "positives per validation fold): fold 2 kept epoch 1 though epoch 2 had higher validation PR-AUC.",
         f"- Weights: eval_common.sample_weights (real total = mutation total; field `weight` on info/low rows). "
         f"lr {cfg['lr']}, {cfg['epochs']} epochs, bf16 autocast on MPS, <= {cfg['max_tokens']} padded tokens per batch, "
         f"max length {cfg['max_len']} (head+tail), comments stripped = {cfg['strip']}.",
         "- Header (attrs, bindgen, pub, detector hit names) is re-derived from the code text for every source, so real "
         "rows (which lack analyzer fields) and corpus rows are encoded the same way.",
         "- Real label-1 vs its fixed version is near chance (ROC above): the encoder mostly learns mutation patterns and "
         "code style, not the audited bugs. Train real labels are noisy (split audit: ~50% agreement).", ""]
    for lvl, fpr in ev.LEVELS.items():
        d = m[lvl]
        ts = [f["thresholds"][lvl] for f in folds]
        L += [f"## {lvl} (target FPR {fpr:.0%} on contract-code corpus negatives; fold thresholds "
              + ", ".join(f"{t:.4f}" for t in ts) + f"; pooled-OOF threshold {m['pooled_thresholds'][lvl]:.4f})", "",
              "| population | alarms (Wilson 95%) |", "|---|---|",
              _row("recall real label-1 (all)", d["recall_real"]), _row("recall real, severity != info", d["recall_real_noninfo"]),
              _row("recall real, severity info", d["recall_real_info"]), _row("recall mutation", d["recall_mutation"]),
              _row("FPR corpus (all)", d["fpr_corpus"]), _row("FPR corpus, contract code", d["fpr_corpus_contract"]),
              _row("FPR paired fixed versions (real label-0)", d["fpr_paired_fixed"]),
              _row("FPR mutation originals", d["fpr_mutation_original"]),
              _row("contract files alarming (clean groups, max over public fns)", d["contract_alarm_share"]),
              *([_row("files holding a real label-1 fn alarming", d["contract_recall_real"])]
                if "contract_recall_real" in d else []),
              f"| recall with pooled-OOF threshold: real {ev.fmt_rate(m_pooled[lvl]['recall_real'])}, "
              f"corpus-contract FPR {ev.fmt_rate(m_pooled[lvl]['fpr_corpus_contract'])} | |", "",
              "| vuln_class (real rows) | recall |", "|---|---|"]
        L += [_row(c, v) for c, v in d["recall_class_real"].items()] + [""]
    L += ["## Folds", "", "| fold | train | val | test | best epoch | seconds | val history |", "|---|---|---|---|---|---|---|"]
    L += [f"| {i} | {f['n_train']} | {f['n_val']} | {f['n_test']} | {f['best_epoch']} | {f['seconds']:.0f} | "
          + "; ".join(f"e{h['epoch']} sel {h['selection']:.3f} prauc {h['val_pr_auc']:.3f}" for h in f["history"]) + " |"
          for i, f in enumerate(folds)]
    if exp:
        L += ["", "## Inner-validation experiments (outer fold 0, validation fold only; no outer-test rows used)", "",
              "| run | model | strip comments | train rows | best epoch | selection | val PR-AUC |", "|---|---|---|---|---|---|---|"]
        for k, v in sorted(exp.items()):
            c, h = exp_cfg.get(k, {}), max(v["history"], key=lambda h: h["selection"])
            L.append(f"| {k} | {c.get('model')} | {c.get('strip')} | {v['n_train']} | {v['best_epoch']} | "
                     f"{h['selection']:.3f} | {h['val_pr_auc']:.3f} |")
    comp = compare_classic(rows, scores)
    if comp:
        out["classic_comparison_pooled"] = comp
        (REPORT / "encoder_cv.json").write_text(json.dumps(out, indent=1, default=float))
        L += ["", "## Against the classical model on the same rows (informational: pooled-OOF thresholds, folds differ)", "",
              "Classical OOF from near/model/reports/classic_cv_avg(hgb,logreg)_oof.npy (5 outer folds); "
              "mean_rank = average of the two scores' ranks.", "",
              "| scores | PR-AUC | ROC real vs contract corpus | real non-info recall block | warn | mutation recall warn |",
              "|---|---|---|---|---|---|"]
        L += [f"| {k} | {v['pr_auc']:.3f} | {v['roc_real']:.3f} | {v['block']} | {v['warn']} | {v['mut_warn']} |"
              for k, v in comp.items()]
    for fj in sorted(OUT.glob("encoder_*/final/fold.json")):
        fi = json.loads(fj.read_text())
        out.setdefault("final_models", {})[str(fj.parent)] = fi
        L += ["", f"## Deployable checkpoint `{fj.parent}/checkpoint`", "",
              f"Trained on {fi['n_train']} train_v1_small rows from 4/5 of the groups (group_folds(rows, 5, SEED + 99)[0]); "
              f"epoch chosen and thresholds set on the other 1/5 ({fi['n_val']} train_v1 rows, never trained on): "
              f"best epoch {fi['best_epoch']}, block {fi['thresholds']['block']:.4f}, warn {fi['thresholds']['warn']:.4f}.",
              "Validation history: " + "; ".join(f"e{h['epoch']} sel {h['selection']:.3f} PR-AUC {h['val_pr_auc']:.3f} "
                                                  f"real non-info warn {h['val_recall_real_noninfo_warn']:.3f}"
                                                  for h in fi["history"])]
        (REPORT / "encoder_cv.json").write_text(json.dumps(out, indent=1, default=float))
    if out["latency"]:
        L += ["", "## Inference latency per function", "", "```", json.dumps(out["latency"], indent=1), "```"]
    (REPORT / "encoder_cv.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


def compare_classic(rows: list[dict], enc: np.ndarray) -> dict | None:
    """Encoder vs the classical avg(hgb,logreg) OOF scores (same row order) and their rank average."""
    p = REPORT / "classic_cv_avg(hgb,logreg)_oof.npy"
    if not p.exists():
        return None
    cl = np.load(p)
    if len(cl) != len(rows):
        return None
    rank = lambda x: np.argsort(np.argsort(x, kind="stable"), kind="stable") / len(x)
    out = {}
    for name, s in {"encoder": enc, "classic avg(hgb,logreg)": cl, "mean_rank": (rank(enc) + rank(cl)) / 2}.items():
        m = ev.metrics(rows, s)
        out[name] = {"pr_auc": m["pr_auc"], "roc_real": m["roc_auc_real_vs_contract_corpus"],
                     "block": ev.fmt_rate(m["block"]["recall_real_noninfo"]),
                     "warn": ev.fmt_rate(m["warn"]["recall_real_noninfo"]),
                     "mut_warn": ev.fmt_rate(m["warn"]["recall_mutation"])}
    return out


def latency(args):
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    rows, _ = load_train()
    cfg = json.loads((OUT / f"encoder_{args.tag}" / "config.json").read_text())
    sample = [rows[i] for i in np.random.RandomState(0).choice(len(rows), 200, replace=False)]
    tok = AutoTokenizer.from_pretrained(cfg["hf_model"])
    t = time.time()
    ids = encode(tok, [input_text(r, bool(cfg["strip"])) for r in sample], cfg["max_len"])
    res = {"n": len(sample), "prep_ms_per_fn": 1000 * (time.time() - t) / len(sample)}
    root = OUT / f"encoder_{args.tag}"
    ckpt = root / "final" / "checkpoint" if (root / "final" / "checkpoint").exists() else root / "fold0" / "checkpoint"
    for name in ("mps", "cpu"):
        dev = torch.device(name)
        model = AutoModelForSequenceClassification.from_pretrained(ckpt).to(dev)
        predict(model, ids, np.arange(8), tok.pad_token_id, dev)
        t = time.time()
        for i in range(len(sample) if name == "mps" else 50):
            predict(model, ids, np.array([i]), tok.pad_token_id, dev)
        res[f"{name}_batch1_ms_per_fn"] = 1000 * (time.time() - t) / (len(sample) if name == "mps" else 50)
        t = time.time()
        predict(model, ids, np.arange(len(sample)), tok.pad_token_id, dev)
        res[f"{name}_batched_ms_per_fn"] = 1000 * (time.time() - t) / len(sample)
    (OUT / f"encoder_{args.tag}" / "latency.json").write_text(json.dumps(res, indent=1))
    print(res)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["cv", "final", "report", "latency"])
    ap.add_argument("--model", default="unixcoder", choices=sorted(MODELS))
    ap.add_argument("--tag", default="unixcoder")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--only-fold", type=int)
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--strip", type=int, default=1)
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--max-tokens", type=int, default=8192)
    ap.add_argument("--train-frac", type=float, default=1.0)
    ap.add_argument("--no-test", action="store_true", help="score only the inner validation fold (experiments)")
    ap.add_argument("--save", type=int, default=1)
    args = ap.parse_args(argv)
    {"cv": cv, "final": cv, "report": report, "latency": latency}[args.cmd](args)


if __name__ == "__main__":
    main()
