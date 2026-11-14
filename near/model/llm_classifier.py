"""Code LLM (Qwen2.5-Coder) + LoRA scoring NEAR Rust functions vulnerable/safe, trained with weighted BCE plus a
pairwise margin-ranking loss over (vulnerable, fixed) and (mutant, original) pairs that share a batch.

Input: encoder.input_text (one-line header: attrs, #[near_bindgen], `pub`, detector hits; comment-stripped code),
header kept whole, code cut to head+tail so the whole input fits max_len, then a fixed suffix whose last token is
pooled by Qwen2ForSequenceClassification. Evaluated with near.model.eval_common under encoder.fold_plan (outer
GroupKFold over `group`; one inner group fold = validation for epoch choice and the block/warn thresholds) on
train_v2 (split-audit drops and relabels already applied by assemble_v2). Training rows come from train_v2_small;
scored rows (validation, outer test, OOF) are all of train_v2. Never reads a test file.

    uv run --with peft python -m near.model.llm_classifier cv --folds 3 --tag qwen05_cv3        # background it
    uv run --with peft python -m near.model.llm_classifier baseline --folds 3                    # v1 HGB recipe, same folds
    uv run --with peft python -m near.model.llm_classifier final --tag qwen05_final              # 4/5 groups + merge
    uv run --with peft python -m near.model.llm_classifier latency --tag qwen05_final
    uv run --with peft python -m near.model.llm_classifier report --tag qwen05_cv3

Inference on the merged model needs only transformers: `load_final()` + `score_rows(rows)`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from collections import defaultdict
from multiprocessing import Pool
from pathlib import Path

import numpy as np

# Cap the MPS caching allocator (default may grow past physical RAM with varying batch shapes and swap the machine)
os.environ.setdefault("PYTORCH_MPS_HIGH_WATERMARK_RATIO", "0.5")
os.environ.setdefault("PYTORCH_MPS_LOW_WATERMARK_RATIO", "0.35")

from near.model import encoder as E  # noqa: E402
from near.model import eval_common as ev  # noqa: E402

DATA, OUT, REPORT = Path("near/data"), Path("near/models"), Path("near/model/reports")
TRAIN, SMALL = DATA / "train_v2.jsonl", DATA / "train_v2_small.jsonl"
FINAL_DIR = OUT / "llm_final"
OOF_FILE = OUT / "llm_oof.jsonl"
BASELINE_DIR = OUT / "llm_baseline_hgb"
MODELS = {"qwen05": "Qwen/Qwen2.5-Coder-0.5B", "qwen15": "Qwen/Qwen2.5-Coder-1.5B"}
LORA_TARGETS = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
SUFFIX = "\n// vulnerable:"
V1_HGB = {"lr": 0.1, "leaves": 31, "svd": 0, "top_tokens": 1000}  # frozen_near_v1 params (info weight unused in v2)


def sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_train(path: Path = TRAIN, small: Path = SMALL) -> tuple[list[dict], set[str]]:
    """train_v2 rows and the ids of train_v2_small. No drop file: assemble_v2 already removed the split-audit drops."""
    for p in (path, small):
        if "test" in Path(p).name:
            raise SystemExit(f"refusing to read a test file in the training stage: {p}")
    with Path(path).open() as fh:
        rows = [json.loads(line) for line in fh]
    with Path(small).open() as fh:
        return rows, {json.loads(line)["id"] for line in fh}


# ---------------------------------------------------------------- inputs

def _inputs(r):
    return E.input_text(r, True)


def encode(tok, texts: list[tuple[str, str]], max_len: int) -> list[list[int]]:
    """Header line + newline kept whole, code head+tail truncated, SUFFIX appended (its last token is pooled)."""
    suffix = tok(SUFFIX, add_special_tokens=False)["input_ids"]
    hs = tok([h + "\n" for h, _ in texts], add_special_tokens=False)["input_ids"]
    bs = tok([b for _, b in texts], add_special_tokens=False)["input_ids"]
    return [E.truncate_ids(h, b, max_len - len(suffix)) + suffix for h, b in zip(hs, bs)]


def token_ids(rows: list[dict], hf_model: str, max_len: int, log=print) -> list[list[int]]:
    """Token ids for every row, cached under near/models/llm_cache/ by (rows, model, max_len, input code)."""
    from transformers import AutoTokenizer
    h = hashlib.sha256()
    for r in rows:
        h.update(r["id"].encode())
    h.update(Path(E.__file__).read_bytes())
    h.update(SUFFIX.encode())
    key = h.hexdigest()[:16]
    cache = OUT / "llm_cache" / f"{hf_model.replace('/', '_')}_{max_len}_{key}.json"
    if cache.exists():
        return json.loads(cache.read_text())
    t = time.time()
    with Pool(16) as p:
        texts = p.map(_inputs, rows, chunksize=256)
    ids = encode(AutoTokenizer.from_pretrained(hf_model), texts, max_len)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(ids))
    log(f"inputs+tokens {time.time() - t:.0f}s, median len {int(np.median([len(s) for s in ids]))}, "
        f"at max_len {sum(len(s) >= max_len for s in ids)}")
    return ids


# ---------------------------------------------------------------- pairs and batches

def pair_edges(rows: list[dict], idx) -> list[tuple[int, int, str]]:
    """(label-1 row, its label-0 pair_id row, kind) with both rows in idx; kind 'real' when the label-1 row is a real
    vulnerability (audit/incident/fix_commit), else 'mutation' (mutant vs the function it was derived from)."""
    inside = {rows[i]["id"]: int(i) for i in idx}
    out = []
    for i in idx:
        r = rows[i]
        j = inside.get(r.get("pair_id"))
        if r["label"] == 1 and j is not None and rows[j]["label"] == 0:
            out.append((int(i), j, "real" if ev.is_real(r) else "mutation"))
    return out


def units(idx, edges) -> list[list[int]]:
    """Connected components of the pair graph over idx (singletons for unpaired rows), members sorted."""
    parent = {int(i): int(i) for i in idx}

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    for a, b, _ in edges:
        parent[find(a)] = find(b)
    comp = defaultdict(list)
    for i in parent:
        comp[find(i)].append(i)
    return [sorted(v) for _, v in sorted(comp.items())]


def unit_batches(us: list[list[int]], lengths: np.ndarray, max_tokens: int, rng, step: int = 64) -> list[list[int]]:
    """Batches of whole units (pair members stay together), bucketed by the unit's longest member rounded up to
    `step`; each batch holds max_tokens // bucket rows: paired units first, the rest filled with singletons, so most
    batches of a bucket share one shape (MPS is slow on varying shapes). Shuffled."""
    buckets = defaultdict(lambda: ([], []))
    for u in us:
        L = int(-(-max(lengths[i] for i in u) // step) * step)
        buckets[L][len(u) == 1].append(u)
    out = []
    for L in sorted(buckets):
        multi, single = (list(x) for x in buckets[L])
        rng.shuffle(multi)
        rng.shuffle(single)
        size = max(1, max_tokens // L)
        while multi or single:
            b = []
            while multi and (not b or len(b) + len(multi[-1]) <= size):
                b += multi.pop()
            while single and len(b) < size:
                b += single.pop()
            out.append(b)
    return [out[i] for i in rng.permutation(len(out))]


def pairs_in_batch(b: list[int], edges_by_pos: dict, pair_w: dict) -> tuple[list[int], list[int], list[float]]:
    """Local (positive, negative) positions and weights of the pairs whose both members are in batch b."""
    loc = {g: k for k, g in enumerate(b)}
    P, N, W = [], [], []
    for g in b:
        for j in edges_by_pos.get(g, ()):
            if j in loc:
                P.append(loc[g]); N.append(loc[j]); W.append(pair_w[(g, j)])
    return P, N, W


def batch_loss(logit, y, w, P, N, W, lam: float, margin: float):
    """Weighted BCE (sum / batch rows) + lam x weighted mean margin-ranking loss max(0, margin - (s_pos - s_neg))."""
    import torch
    import torch.nn.functional as F
    loss = (F.binary_cross_entropy_with_logits(logit, y, reduction="none") * w).sum() / len(y)
    if P and lam:
        pi, ni = torch.tensor(P, device=logit.device), torch.tensor(N, device=logit.device)
        pw = torch.tensor(W, dtype=logit.dtype, device=logit.device)
        loss = loss + lam * (F.relu(margin - (logit[pi] - logit[ni])) * pw).sum() / len(P)
    return loss


# ---------------------------------------------------------------- model

def device():
    import torch
    return torch.device("mps" if torch.backends.mps.is_available() else "cpu")


def build_model(hf_model: str, r: int, dev, grad_ckpt: bool = False):
    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(hf_model)
    model = AutoModelForSequenceClassification.from_pretrained(hf_model, num_labels=1, dtype=torch.float32)
    model.config.pad_token_id = tok.pad_token_id
    cfg = LoraConfig(r=r, lora_alpha=2 * r, lora_dropout=0.05, task_type="SEQ_CLS", target_modules=LORA_TARGETS)
    model = get_peft_model(model, cfg).to(dev)
    if grad_ckpt:  # without it 8 x 512 tokens needs > 14 GB on MPS (fp32 LoRA input casts kept for backward)
        model.base_model.model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    return model, tok


def collate(ids: list[list[int]], pad: int, dev, step: int = 64):
    import torch
    n = int(-(-max(map(len, ids)) // step) * step)
    x = torch.full((len(ids), n), pad, dtype=torch.long)
    m = torch.zeros((len(ids), n), dtype=torch.long)
    for i, s in enumerate(ids):
        x[i, :len(s)] = torch.tensor(s)
        m[i, :len(s)] = 1
    return x.to(dev), m.to(dev)


def predict(model, ids: list[list[int]], idx, pad: int, dev, max_tokens: int = 16384) -> np.ndarray:
    """Sigmoid scores for rows idx (bf16 autocast on MPS), in idx order."""
    import torch
    idx = np.asarray(idx, int)
    lengths = np.array([len(s) for s in ids])
    out = np.zeros(len(ids))
    model.eval()
    with torch.no_grad():
        for b in E.batches(lengths, idx, max_tokens, max_batch=128):
            x, m = collate([ids[i] for i in b], pad, dev)
            with torch.autocast(dev.type, dtype=torch.bfloat16, enabled=dev.type == "mps"):
                logit = model(input_ids=x, attention_mask=m).logits.float().squeeze(-1)
            out[b] = torch.sigmoid(logit).cpu().numpy()
    if dev.type == "mps":
        torch.mps.empty_cache()
    return out[idx]


def train_weights(rows: list[dict], tr: np.ndarray, corpus_frac: float) -> np.ndarray:
    """eval_common.sample_weights on tr (field `weight` = relabel/confidence weight, real total = mutation total),
    corpus rows x 1/corpus_frac (they are subsampled per epoch), normalized to mean 1 over tr."""
    w = np.zeros(len(rows))
    w[tr] = ev.sample_weights([rows[i] for i in tr])
    corp = np.array([rows[i]["source"] == "corpus" for i in tr])
    w[tr[corp]] /= corpus_frac
    w[tr] *= len(tr) / w[tr].sum()
    return w


def pair_weights(rows: list[dict], edges, real_pair_weight: float) -> dict:
    return {(a, b): (real_pair_weight * float(rows[a].get("weight") or 1.0) if k == "real" else 1.0)
            for a, b, k in edges}


def train_fold(args, rows, ids, pad, tr, val, te, fdir: Path, log) -> dict:
    """LoRA fine-tune on tr; keep the epoch with the best eval_common.selection_score on val; score val and te."""
    import torch
    torch.manual_seed(ev.SEED)
    dev = device()
    model, _ = build_model(MODELS[args.model], args.lora_r, dev, bool(args.grad_ckpt))
    y = torch.tensor([float(r["label"]) for r in rows])
    w = torch.tensor(train_weights(rows, tr, args.corpus_frac), dtype=torch.float32)
    lengths = np.array([len(s) for s in ids])
    edges = pair_edges(rows, tr)
    by_pos = defaultdict(list)
    for a, b, _ in edges:
        by_pos[a].append(b)
    pw = pair_weights(rows, edges, args.real_pair_weight)
    us = units(tr, edges)
    corpus_single = np.array([len(u) == 1 and rows[u[0]]["source"] == "corpus" for u in us])
    rng = np.random.RandomState(ev.SEED)

    def epoch_units():
        keep = ~corpus_single | (rng.rand(len(us)) < args.corpus_frac)
        return [u for u, k in zip(us, keep) if k]

    plan = [unit_batches(epoch_units(), lengths, args.max_tokens, rng) for _ in range(args.epochs)]
    steps = sum(map(len, plan))
    n_real = sum(k == "real" for *_, k in edges)
    log(f"    pairs: real {n_real}, mutation {len(edges) - n_real}; units {len(us)}; "
        f"rows/epoch {[sum(map(len, p)) for p in plan]}; steps {steps}")
    params = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(params, lr=args.lr, weight_decay=0.01)
    from transformers import get_linear_schedule_with_warmup
    sched = get_linear_schedule_with_warmup(opt, int(0.06 * steps), steps)
    val_rows = [rows[i] for i in val]
    best, hist, t0, step, run = (-1.0, None, None, None), [], time.time(), 0, []
    for epoch, batches in enumerate(plan):
        model.train()
        for b in batches:
            x, m = collate([ids[i] for i in b], pad, dev)
            with torch.autocast(dev.type, dtype=torch.bfloat16, enabled=dev.type == "mps"):
                logit = model(input_ids=x, attention_mask=m).logits.float().squeeze(-1)
            P, N, W = pairs_in_batch(b, by_pos, pw)
            loss = batch_loss(logit, y[b].to(dev), w[b].to(dev), P, N, W, args.pair_lambda, args.margin)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(params, 1.0)
            opt.step(); sched.step(); opt.zero_grad(set_to_none=True)
            step += 1
            run.append(loss.item())
            if step % 50 == 0 and dev.type == "mps":
                torch.mps.empty_cache()
            if step % 200 == 0:
                log(f"    step {step}/{steps} loss(avg200) {np.mean(run[-200:]):.4f} {time.time() - t0:.0f}s")
        s_val = predict(model, ids, val, pad, dev)
        met = ev.metrics(val_rows, s_val)
        hist.append({"epoch": epoch + 1, "selection": ev.selection_score(val_rows, s_val), "val_pr_auc": met["pr_auc"],
                     "val_pair_rank_real": met["pair_rank_acc"]["rate"],
                     "val_pair_rank_mutation": mutation_pair_rank(val_rows, s_val)["rate"],
                     "val_recall_real_warn": met["warn"]["recall_real"]["rate"],
                     "val_recall_mutation_warn": met["warn"]["recall_mutation"]["rate"], "seconds": time.time() - t0})
        log(f"    epoch {epoch + 1}: {hist[-1]}")
        if hist[-1]["selection"] > best[0]:
            best = (hist[-1]["selection"], epoch + 1,
                    {k: v.detach().to("cpu", copy=True) for k, v in model.state_dict().items() if "lora" in k
                     or "score" in k}, s_val)
    if best[1] != args.epochs:
        model.load_state_dict(best[2], strict=False)
    s_val = best[3]
    thr = ev.thresholds_from(val_rows, s_val)
    s_te = predict(model, ids, te, pad, dev) if len(te) else np.zeros(0)
    model.save_pretrained(fdir / "adapter")
    write_scores(fdir / "scores_val.jsonl", rows, val, s_val)
    write_scores(fdir / "scores_test.jsonl", rows, te, s_te)
    return {"best_epoch": best[1], "history": hist, "thresholds": thr, "n_train": len(tr), "n_val": len(val),
            "n_test": len(te), "pairs_real": n_real, "pairs_mutation": len(edges) - n_real, "steps": steps,
            "seconds": time.time() - t0}, model


def write_scores(path: Path, rows, idx, s):
    with path.open("w") as fh:
        for i, v in zip(idx, s):
            fh.write(json.dumps({"id": rows[i]["id"], "score": float(v)}) + "\n")


def read_scores(path: Path) -> dict[str, float]:
    with path.open() as fh:
        return {d["id"]: d["score"] for d in map(json.loads, fh)}


def final_split(rows):
    """Deployable model: 4/5 of the groups train, the other 1/5 picks the epoch and sets the thresholds."""
    return ev.group_folds(rows, 5, ev.SEED + 99)[0]


def _logger(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    logf = (root / "train.log").open("a")

    def log(msg):
        print(msg, flush=True)
        logf.write(msg + "\n")
        logf.flush()
    return log


def cv(args):
    root = OUT / f"llm_{args.tag}"
    log = _logger(root)
    rows, small = load_train()
    hf = MODELS[args.model]
    ids = token_ids(rows, hf, args.max_len, log)
    pad = _pad_id(hf)
    log(f"{args.cmd} {args.tag}: {len(rows)} rows ({len(small)} small), median len "
        f"{int(np.median([len(s) for s in ids]))}, at max_len {sum(len(s) >= args.max_len for s in ids)}")
    cfg = vars(args) | {"hf_model": hf, "train_sha256": sha256(TRAIN), "small_sha256": sha256(SMALL),
                        "encoder_py_sha256": sha256(Path(E.__file__)), "suffix": SUFFIX, "lora_targets": LORA_TARGETS}
    (root / "config.json").write_text(json.dumps(cfg, indent=1))
    in_small = np.array([r["id"] in small for r in rows])
    if args.cmd == "final":
        tr, val = final_split(rows)
        plan, names = [(tr, val, val[:0])], ["final"]
    else:
        plan, names = E.fold_plan(rows, args.folds), [f"fold{f}" for f in range(args.folds)]
    for f, (tr, val, te) in enumerate(plan):
        if args.only_fold is not None and f != args.only_fold:
            continue
        fdir = root / names[f]
        if (fdir / "fold.json").exists():
            log(f"  {names[f]} done, skipping")
            continue
        fdir.mkdir(exist_ok=True)
        tr = tr[in_small[tr]]
        if args.no_test:
            te = te[:0]
        log(f"  {names[f]}: train {len(tr)} val {len(val)} test {len(te)}")
        info, model = train_fold(args, rows, ids, pad, tr, val, te, fdir, log)
        if args.cmd == "final":
            info["merge"] = merge_and_save(model, hf, rows, ids, val, pad, info, cfg, log)
        (fdir / "fold.json").write_text(json.dumps(info, indent=1))
        log(f"  {names[f]} done in {info['seconds']:.0f}s: best epoch {info['best_epoch']} thresholds {info['thresholds']}")
        del model


def _pad_id(hf):
    from transformers import AutoTokenizer
    return AutoTokenizer.from_pretrained(hf).pad_token_id


# ---------------------------------------------------------------- deployable merged model

def merge_and_save(model, hf, rows, ids, val, pad, info, cfg, log, out: Path = FINAL_DIR) -> dict:
    """Merge LoRA into the base weights, save a plain transformers checkpoint (bf16) + oracle.json, and check the
    merged model reproduces the adapter's scores on 512 validation rows."""
    import torch
    from transformers import AutoTokenizer
    dev = device()
    sample = np.sort(np.random.RandomState(0).choice(val, min(512, len(val)), replace=False))
    before = predict(model, ids, sample, pad, dev)
    merged = model.merge_and_unload()
    merged.to(torch.bfloat16).save_pretrained(out)
    AutoTokenizer.from_pretrained(hf).save_pretrained(out)
    meta = {"base_model": hf, "max_len": cfg["max_len"], "suffix": SUFFIX, "input": "near.model.encoder.input_text "
            "(strip=True): header + '\\n' + head/tail-truncated code + suffix; sigmoid(logit) = risk",
            "thresholds": info["thresholds"], "levels_fpr_on_contract_corpus": ev.LEVELS,
            "best_epoch": info["best_epoch"], "train_sha256": cfg["train_sha256"], "small_sha256": cfg["small_sha256"],
            "train_rows": info["n_train"], "val_rows": info["n_val"], "split": "group_folds(train_v2, 5, SEED+99)[0]",
            "config": cfg}
    (out / "oracle.json").write_text(json.dumps(meta, indent=1))
    del merged
    m2 = load_final(out, dev)[0]
    after = predict(m2, ids, sample, pad, dev)
    from scipy.stats import spearmanr
    res = {"n": len(sample), "max_abs_diff": float(np.abs(after - before).max()),
           "spearman": float(spearmanr(before, after).statistic)}
    log(f"  merged model saved to {out}: parity {res}")
    return res


def load_final(path: Path = FINAL_DIR, dev=None):
    """(model, tokenizer, oracle meta) of the merged deployable checkpoint: plain transformers, no peft."""
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    dev = dev or device()
    dtype = torch.bfloat16 if dev.type == "mps" else torch.float32
    model = AutoModelForSequenceClassification.from_pretrained(path, dtype=dtype).to(dev).eval()
    return model, AutoTokenizer.from_pretrained(path), json.loads((Path(path) / "oracle.json").read_text())


def score_rows(fn_rows: list[dict], loaded=None) -> list[float]:
    """Risk 0..1 per function dict (keys: code, fn, path?, attrs?, is_near_bindgen?) with the merged model."""
    model, tok, meta = loaded or load_final()
    ids = encode(tok, [E.input_text(r, True) for r in fn_rows], meta["max_len"])
    dev = next(model.parameters()).device
    return predict(model, ids, np.arange(len(ids)), tok.pad_token_id, dev).tolist()


# ---------------------------------------------------------------- baseline: v1 HGB recipe on the same folds

def baseline(args):
    from near.model import train_classic as tc
    log = _logger(BASELINE_DIR)
    rows, small = load_train()
    t = time.time()
    A, T, C = tc.featurize_rows(rows)
    log(f"baseline: featurized {len(rows)} rows in {time.time() - t:.0f}s")
    in_small = np.array([r["id"] in small for r in rows])
    y = np.array([r["label"] for r in rows])
    for f, (tr, val, te) in enumerate(E.fold_plan(rows, args.folds)):
        fdir = BASELINE_DIR / f"fold{f}"
        fdir.mkdir(parents=True, exist_ok=True)
        tr = tr[in_small[tr]]
        t = time.time()
        m = tc.fit_model("hgb", V1_HGB, A[tr], T[tr], C[tr], y[tr], ev.sample_weights([rows[i] for i in tr]))
        s_val, s_te = (tc.predict_model(m, A[ix], T[ix], C[ix]) for ix in (val, te))
        thr = ev.thresholds_from([rows[i] for i in val], s_val)
        write_scores(fdir / "scores_val.jsonl", rows, val, s_val)
        write_scores(fdir / "scores_test.jsonl", rows, te, s_te)
        info = {"params": V1_HGB, "thresholds": thr, "n_train": len(tr), "n_val": len(val), "n_test": len(te),
                "seconds": time.time() - t}
        (fdir / "fold.json").write_text(json.dumps(info, indent=1))
        log(f"  fold {f}: {info}")


# ---------------------------------------------------------------- metrics and report

def length_key(r: dict, partner: dict) -> str:
    """Pairs split by code length: a fix usually adds code, so 'shorter = riskier' alone ranks most pairs right."""
    return "len=vuln shorter" if len(r["code"]) < len(partner["code"]) else "len=vuln same or longer"


def mutation_pair_rank(rows: list[dict], scores, length: str | None = None) -> dict:
    """Share of (mutant, original) pairs where the mutant scores higher (ties half); `length` = a length_key value
    restricts to that subset."""
    pos = {r["id"]: i for i, r in enumerate(rows)}
    wins = []
    for i, r in enumerate(rows):
        j = pos.get(r.get("pair_id"))
        if r["source"] == "mutation" and r["label"] == 1 and j is not None and rows[j]["label"] == 0 \
                and (length is None or length_key(r, rows[j]) == length):
            wins.append(1.0 if scores[i] > scores[j] else 0.5 if scores[i] == scores[j] else 0.0)
    k, n = float(sum(wins)), len(wins)
    lo, hi = ev.wilson(k, n)
    return {"k": k, "n": n, "rate": k / n if n else float("nan"), "lo": lo, "hi": hi}


def real_pairs_detail(rows: list[dict], scores) -> dict:
    """Real pair ranking split by the positive's source and relabel verdict, plus mean score gap."""
    pos = {r["id"]: i for i, r in enumerate(rows)}
    by = defaultdict(list)
    for i, r in enumerate(rows):
        j = pos.get(r.get("pair_id"))
        if ev.is_real(r) and r["label"] == 1 and j is not None and rows[j]["label"] == 0:
            win = 1.0 if scores[i] > scores[j] else 0.5 if scores[i] == scores[j] else 0.0
            for key in ("all", f"source={r['source']}", f"verdict={r.get('relabel_verdict') or 'none (v2 fix commit)'}",
                        length_key(r, rows[j])):
                by[key].append((win, scores[i] - scores[j]))
    out = {}
    for key, v in sorted(by.items()):
        k, n = sum(x for x, _ in v), len(v)
        lo, hi = ev.wilson(k, n)
        out[key] = {"k": k, "n": n, "rate": k / n, "lo": lo, "hi": hi, "mean_gap": float(np.mean([g for _, g in v]))}
    return out


def real_recall_split(rows: list[dict], hit: np.ndarray) -> dict:
    """Recall on real label-1 rows by relabel verdict (confirmed / plausible / none = new v2 fix commits) and source."""
    real_pos = np.array([ev.is_real(r) and r["label"] == 1 for r in rows])
    ver = np.array([r.get("relabel_verdict") or "none" for r in rows], object)
    src = np.array([r["source"] for r in rows], object)
    out = {f"verdict={v}": ev.rate(hit, real_pos & (ver == v)) for v in ("confirmed", "plausible", "none")}
    out |= {f"source={s}": ev.rate(hit, real_pos & (src == s)) for s in ev.REAL}
    return out


def oof_scores(root: Path, rows: list[dict]):
    """Pooled outer-fold scores and nested decisions (each fold's validation thresholds)."""
    pos = {r["id"]: i for i, r in enumerate(rows)}
    scores = np.full(len(rows), np.nan)
    fold = np.full(len(rows), -1)
    thr_row = {lvl: np.full(len(rows), np.inf) for lvl in ev.LEVELS}
    folds = []
    for f, fdir in enumerate(sorted(root.glob("fold[0-9]*"))):
        if not (fdir / "fold.json").exists():
            continue
        info = json.loads((fdir / "fold.json").read_text())
        for k, v in read_scores(fdir / "scores_test.jsonl").items():
            scores[pos[k]], fold[pos[k]] = v, int(fdir.name[4:])
            for lvl in ev.LEVELS:
                thr_row[lvl][pos[k]] = info["thresholds"][lvl]
        folds.append(info | {"name": fdir.name})
    return scores, fold, {lvl: scores >= thr_row[lvl] for lvl in ev.LEVELS}, folds


def summarize(rows, scores, dec) -> dict:
    m = ev.metrics(rows, scores, dec)
    m["pair_rank_mutation"] = mutation_pair_rank(rows, scores)
    m["pair_rank_mutation_by_length"] = {k: mutation_pair_rank(rows, scores, k)
                                         for k in ("len=vuln shorter", "len=vuln same or longer")}
    m["real_pairs_detail"] = real_pairs_detail(rows, scores)
    for lvl in ev.LEVELS:
        m[lvl]["recall_real_split"] = real_recall_split(rows, dec[lvl])
    return m


def _sub(rows, scores, dec, mask):
    idx = np.flatnonzero(mask)
    return [rows[i] for i in idx], scores[idx], {k: v[idx] for k, v in dec.items()}


def report(args):
    rows, _ = load_train()
    root = OUT / f"llm_{args.tag}"
    cfg = json.loads((root / "config.json").read_text())
    s, fold, dec, folds = oof_scores(root, rows)
    done = ~np.isnan(s)
    if not done.any():
        raise SystemExit("no outer-fold scores yet")
    sub_rows, sub_s, sub_dec = _sub(rows, s, dec, done)
    if done.all():
        with OOF_FILE.open("w") as fh:
            for r, v, f in zip(rows, s, fold):
                fh.write(json.dumps({"id": r["id"], "score": float(v), "fold": int(f)}) + "\n")
    m = summarize(sub_rows, sub_s, sub_dec)
    comp = {f"llm ({args.tag})": m}
    bs, _, bdec, bfolds = oof_scores(BASELINE_DIR, rows) if BASELINE_DIR.exists() else (None, None, None, [])
    if bfolds and not np.isnan(bs[done]).any():
        comp["v1 HGB recipe (same folds/rows)"] = summarize(*_sub(rows, bs, bdec, done))
        rank = lambda x: np.argsort(np.argsort(x, kind="stable"), kind="stable") / len(x)
        mr = (rank(sub_s) + rank(bs[done])) / 2  # ranks are pooled, so its thresholds are pooled too (optimistic)
        thr = ev.thresholds_from(sub_rows, mr)
        comp["mean rank llm+hgb (pooled thresholds)"] = summarize(sub_rows, mr, {k: mr >= t for k, t in thr.items()})
    neg_len = -np.array([len(r["code"]) for r in sub_rows], float)  # control scorer: shorter code = riskier
    thr = ev.thresholds_from(sub_rows, neg_len)
    comp["control: -len(code) (pooled thresholds)"] = summarize(sub_rows, neg_len, {k: neg_len >= t for k, t in thr.items()})
    lat = OUT / f"llm_{args.final_tag}" / "latency.json"
    fin = OUT / f"llm_{args.final_tag}" / "final" / "fold.json"
    extra = {p.parent.parent.name: json.loads(p.read_text()) | {"config": json.loads((p.parent.parent / "config.json")
             .read_text())} for p in OUT.glob("llm_xp_*/fold0/fold.json")}
    out = {"tag": args.tag, "config": cfg, "n_scored": int(done.sum()), "folds": folds, "baseline_folds": bfolds,
           "metrics": comp, "latency": json.loads(lat.read_text()) if lat.exists() else None,
           "final": json.loads(fin.read_text()) if fin.exists() else None, "fold0_experiments": extra,
           "oof_file": str(OOF_FILE) if done.all() else None,
           "oof_sha256": sha256(OOF_FILE) if done.all() else None}
    REPORT.mkdir(parents=True, exist_ok=True)
    (REPORT / "llm_v2_cv.json").write_text(json.dumps(out, indent=1, default=float))
    (REPORT / "llm_v2_cv.md").write_text(render_md(out, rows) + "\n")
    print(render_md(out, rows))


def _pct(d):
    return ev.fmt_rate(d) if d["n"] else "n/a"


def render_md(out: dict, rows) -> str:
    cfg, comp = out["config"], out["metrics"]
    names = list(comp)
    L = [f"# Code LLM v2: nested grouped CV on train_v2 ({cfg['hf_model']} + LoRA r{cfg['lora_r']}, pairwise loss)", "",
         f"{out['n_scored']} of {len(rows)} train_v2 rows scored out-of-fold ({len(out['folds'])} of {cfg['folds']} outer "
         "folds). Thresholds per fold from its inner validation fold (contract-code corpus negatives).", "",
         "## Headline (pooled outer folds; nested thresholds except the mean-rank row)", "",
         "| model | PR-AUC | ROC real vs contract corpus | ROC real vs its fixed | pair rank real (vuln > fixed) "
         "| pair rank mutation | real recall block | real recall warn | mutation recall warn | FPR contract corpus warn |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    for n in names:
        m = comp[n]
        L.append(f"| {n} | {m['pr_auc']:.3f} | {m['roc_auc_real_vs_contract_corpus']:.3f} | {m['roc_auc_real_vs_fixed']:.3f}"
                 f" | {_pct(m['pair_rank_acc'])} | {_pct(m['pair_rank_mutation'])} | {_pct(m['block']['recall_real'])}"
                 f" | {_pct(m['warn']['recall_real'])} | {_pct(m['warn']['recall_mutation'])}"
                 f" | {_pct(m['warn']['fpr_corpus_contract'])} |")
    llm, ctrl = comp[names[0]], comp.get("control: -len(code) (pooled thresholds)")
    hgb = comp.get("v1 HGB recipe (same folds/rows)")
    hard = "len=vuln same or longer"
    if ctrl and hgb:
        L += ["", "### Reading the pair numbers", "",
              f"- A fix usually adds code. The control scorer 'shorter function = riskier' (no model) ranks "
              f"{_pct(ctrl['pair_rank_acc'])} of real pairs and {_pct(ctrl['pair_rank_mutation'])} of mutation pairs right, "
              "more than either model, so pair ranking alone does not show that a model sees the bug.",
              f"- On the real pairs where the vulnerable version is not shorter than its fix "
              f"(n = {llm['real_pairs_detail'].get(hard, {'n': 0})['n']}), the LLM ranks "
              f"{_pct(llm['real_pairs_detail'].get(hard, {'k': 0, 'n': 0}))} and the v1 HGB recipe "
              f"{_pct(hgb['real_pairs_detail'].get(hard, {'k': 0, 'n': 0}))}: both at chance. The LLM's gain over HGB "
              f"comes from the pairs where the vulnerable version is shorter ({_pct(llm['real_pairs_detail']['len=vuln shorter'])} "
              f"vs {_pct(hgb['real_pairs_detail']['len=vuln shorter'])}), which is what a 'missing check / missing code' cue "
              "would give. Mutation pairs (templated edits) are ranked right whatever their length.",
              f"- Against corpus code the LLM is not better than the v1 HGB recipe: real recall at warn "
              f"{_pct(llm['warn']['recall_real'])} vs {_pct(hgb['warn']['recall_real'])}, PR-AUC {llm['pr_auc']:.3f} vs "
              f"{hgb['pr_auc']:.3f}."]
        e1_better = [f["name"] for f in out["folds"] if len(f["history"]) > 1
                     and f["history"][0]["val_pair_rank_real"] > f["history"][-1]["val_pair_rank_real"]]
        if e1_better:
            L.append(f"- On the validation folds, real pair ranking was higher after epoch 1 than after the last epoch in "
                     f"{len(e1_better)} of {len(out['folds'])} folds ({', '.join(e1_better)}), while the protocol's selection "
                     "score (recall against corpus) preferred the last epoch: the second epoch traded pair signal for recall "
                     "against corpus code.")
        L.append("- 'mean gap' below = mean of score(vulnerable) - score(fixed) over pairs (characters for the control).")
    L += ["", "## Protocol", "",
          f"- Rows: {TRAIN} (sha256 {cfg['train_sha256'][:16]}...), split-audit drops and blind relabels applied by "
          "assemble_v2; no test file read. Training rows: train_v2_small members of each inner-train split.",
          f"- Folds: near.model.encoder.fold_plan ({cfg['folds']} outer GroupKFold folds over `group`, "
          f"eval_common seed {ev.SEED}; validation = first inner group fold of the outer-train split, never trained on).",
          f"- Model: {cfg['hf_model']}, LoRA r {cfg['lora_r']} alpha {2 * cfg['lora_r']} on {', '.join(LORA_TARGETS)}, "
          f"score head trained; fp32 master weights, bf16 autocast on MPS; lr {cfg['lr']}, {cfg['epochs']} epochs, "
          f"<= {cfg['max_tokens']} padded tokens per batch, max length {cfg['max_len']} (header whole, code head+tail), "
          f"gradient checkpointing {bool(cfg.get('grad_ckpt'))}.",
          f"- Loss: weighted BCE (eval_common.sample_weights: field `weight` = relabel/confidence weight; real label-1 total "
          f"= mutation total) + {cfg['pair_lambda']} x margin-ranking (margin {cfg['margin']}) over pairs whose two members "
          f"share a batch (batches are built from whole pair units). Real pair weight {cfg['real_pair_weight']} x the "
          f"positive's weight; mutation pair weight 1. Corpus negatives subsampled to {cfg['corpus_frac']:.0%} per epoch "
          "(fresh draw each epoch, weight x 1/frac).",
          "- Epoch kept by eval_common.selection_score on the validation fold; thresholds = 1% / 5% FPR on its contract-code "
          "corpus negatives.",
          "- Baseline: the frozen v1 HGB recipe (params " + json.dumps(V1_HGB) + ", same features as train_classic) fitted on "
          "the same training rows of the same folds, thresholds from the same validation fold.", ""]
    for lvl, fpr in ev.LEVELS.items():
        L += [f"## {lvl} (target FPR {fpr:.0%} on contract-code corpus negatives)", "",
              "| population | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
        pops = [("recall real label-1", "recall_real"), ("recall mutation", "recall_mutation"),
                ("FPR corpus (all)", "fpr_corpus"), ("FPR corpus, contract code", "fpr_corpus_contract"),
                ("FPR real fixed versions", "fpr_paired_fixed"), ("FPR mutation originals", "fpr_mutation_original"),
                ("contract files alarming (clean groups)", "contract_alarm_share"),
                ("files holding a real label-1 fn alarming", "contract_recall_real")]
        L += [f"| {lab} | " + " | ".join(_pct(comp[n][lvl][k]) for n in names) + " |" for lab, k in pops]
        keys = list(comp[names[0]][lvl]["recall_real_split"])
        L += [f"| recall real, {k} | " + " | ".join(_pct(comp[n][lvl]["recall_real_split"][k]) for n in names) + " |"
              for k in keys]
        classes = list(comp[names[0]][lvl]["recall_class_real"])
        L += [f"| recall real, class {c} | " + " | ".join(_pct(comp[n][lvl]["recall_class_real"].get(c, {"n": 0}))
                                                           for n in names) + " |" for c in classes]
        L.append("")
    L += ["## Real (vulnerable, fixed) pairs in detail", "", "| subset | " + " | ".join(
        f"{n} rank acc | mean gap" for n in names) + " |", "|---|" + "---|---|" * len(names)]
    keys = sorted({k for n in names for k in comp[n]["real_pairs_detail"]}, key=lambda k: (k != "all", k))
    for k in keys:
        cells = []
        for n in names:
            d = comp[n]["real_pairs_detail"].get(k)
            cells += [_pct(d), f"{d['mean_gap']:+.3f}"] if d else ["n/a", ""]
        L.append(f"| {k} | " + " | ".join(cells) + " |")
    L += ["", "Mutation (mutant, original) pairs by length: " + "; ".join(
        f"{n}: " + ", ".join(f"{k} {_pct(v)}" for k, v in comp[n]["pair_rank_mutation_by_length"].items()) for n in names)]
    L += ["", "## Folds", "", "| fold | train | val | test | real pairs | mutation pairs | best epoch | seconds | history |",
          "|---|---|---|---|---|---|---|---|---|"]
    for f in out["folds"]:
        L.append(f"| {f['name']} | {f['n_train']} | {f['n_val']} | {f['n_test']} | {f['pairs_real']} | "
                 f"{f['pairs_mutation']} | {f['best_epoch']} | {f['seconds']:.0f} | " + "; ".join(
                     f"e{h['epoch']} sel {h['selection']:.3f} prauc {h['val_pr_auc']:.3f} pair-real "
                     f"{h['val_pair_rank_real']:.3f} pair-mut {h['val_pair_rank_mutation']:.3f}" for h in f["history"]) + " |")
    if out["fold0_experiments"]:
        L += ["", "## Fold-0 experiments (validation fold only; outer-test rows not used)", "",
              "| run | model | pair lambda | best epoch | selection | val PR-AUC | val pair rank real | val pair rank mutation |",
              "|---|---|---|---|---|---|---|---|"]
        for k, v in sorted(out["fold0_experiments"].items()):
            h = v["history"][v["best_epoch"] - 1]
            L.append(f"| {k} | {v['config']['hf_model']} | {v['config']['pair_lambda']} | {v['best_epoch']} | "
                     f"{h['selection']:.3f} | {h['val_pr_auc']:.3f} | {h['val_pair_rank_real']:.3f} | "
                     f"{h['val_pair_rank_mutation']:.3f} |")
    if out["final"]:
        fi = out["final"]
        L += ["", f"## Deployable merged model `{FINAL_DIR}`", "",
              f"LoRA merged into the base weights, saved bf16 as a plain transformers Qwen2ForSequenceClassification "
              f"(load with near.model.llm_classifier.load_final, no peft). Trained on {fi['n_train']} train_v2_small rows of "
              f"4/5 of the groups (group_folds(rows, 5, SEED + 99)[0]); epoch and thresholds from the other 1/5 "
              f"({fi['n_val']} train_v2 rows, never trained on): best epoch {fi['best_epoch']}, block "
              f"{fi['thresholds']['block']:.4f}, warn {fi['thresholds']['warn']:.4f}. Merge parity on {fi['merge']['n']} "
              f"validation rows: max |diff| {fi['merge']['max_abs_diff']:.4f}, Spearman {fi['merge']['spearman']:.4f}.",
              "Validation history: " + "; ".join(f"e{h['epoch']} sel {h['selection']:.3f} PR-AUC {h['val_pr_auc']:.3f} "
                                                  f"pair-real {h['val_pair_rank_real']:.3f}" for h in fi["history"])]
    if out["latency"]:
        L += ["", "## Inference latency per function (merged model)", "", "```", json.dumps(out["latency"], indent=1), "```"]
    if out["oof_file"]:
        L += ["", f"OOF scores: {out['oof_file']} (sha256 {out['oof_sha256'][:16]}...)."]
    return "\n".join(L)


def latency(args):
    import torch
    rows, _ = load_train()
    sample = [rows[i] for i in np.random.RandomState(0).choice(len(rows), 200, replace=False)]
    res = {"n": len(sample)}
    for name in ("mps", "cpu"):
        dev = torch.device(name)
        loaded = load_final(FINAL_DIR, dev)
        model, tok, meta = loaded
        t = time.time()
        ids = encode(tok, [E.input_text(r, True) for r in sample], meta["max_len"])
        res["prep_ms_per_fn"] = 1000 * (time.time() - t) / len(sample)
        predict(model, ids, np.arange(8), tok.pad_token_id, dev)
        n1 = len(sample) if name == "mps" else 30
        t = time.time()
        for i in range(n1):
            predict(model, ids, np.array([i]), tok.pad_token_id, dev)
        res[f"{name}_batch1_ms_per_fn"] = 1000 * (time.time() - t) / n1
        nb = len(sample) if name == "mps" else 60
        t = time.time()
        predict(model, ids, np.arange(nb), tok.pad_token_id, dev)
        res[f"{name}_batched_ms_per_fn"] = 1000 * (time.time() - t) / nb
        res[f"{name}_dtype"] = str(next(model.parameters()).dtype)
        del model
    res["threads_cpu"] = torch.get_num_threads()
    (OUT / f"llm_{args.tag}").mkdir(parents=True, exist_ok=True)
    (OUT / f"llm_{args.tag}" / "latency.json").write_text(json.dumps(res, indent=1))
    print(res)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["cv", "final", "report", "latency", "baseline"])
    ap.add_argument("--model", default="qwen05", choices=sorted(MODELS))
    ap.add_argument("--tag", default="qwen05_cv3")
    ap.add_argument("--final-tag", default="qwen05_final", help="report: where latency/final info live")
    ap.add_argument("--folds", type=int, default=3)
    ap.add_argument("--only-fold", type=int)
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--max-tokens", type=int, default=4096)
    ap.add_argument("--corpus-frac", type=float, default=0.3)
    ap.add_argument("--grad-ckpt", type=int, default=1)
    ap.add_argument("--pair-lambda", type=float, default=1.0)
    ap.add_argument("--margin", type=float, default=1.0)
    ap.add_argument("--real-pair-weight", type=float, default=5.0)
    ap.add_argument("--no-test", action="store_true", help="score only the validation fold (experiments)")
    args = ap.parse_args(argv)
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    {"cv": cv, "final": cv, "report": report, "latency": latency, "baseline": baseline}[args.cmd](args)


if __name__ == "__main__":
    main()
