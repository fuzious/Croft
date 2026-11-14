"""Classical v2: gradient boosting on function + file/crate context, under the shared nested grouped-CV protocol.

Train file: near/data/train_v2.jsonl. The split-audit drops and the relabels are already applied there, so no drop
file is used. The sealed tests are never read. Candidates, all on non-trivial functions; trivial functions are not
scored and never alarm, as in the frozen v1 model (near.model.freeze):
- `v1_recipe`: the frozen v1 recipe as is. HGB with lr 0.1, 31 leaves, 300 iters and l2 1.0, on analyzer features of
  the function alone plus the top 1000 chi2 code tokens, with protocol weights `eval_common.sample_weights(info=0.3)`.
  It uses the v2 `weight` field (relabel / triage confidence) and fixed params. This is the baseline.
- `v1_recipe_v1w`: the same, with the pre-relabel weights (`weight_v1` where the relabel set one; new fix-commit rows
  keep their triage weight). It isolates what the new weights do.
- `ctx_fixed`: v1 params on the v2 features: analyzer features with the file passed in, per-detector hit counts and
  near.model.context features, plus tokens.
- `file_only` / `file_det`: attribution steps between v1_recipe and ctx_fixed: analyzer features computed with the
  file (callback detection sees the scheduling code), then plus per-detector counts.
- `ctx_fixed_noera` / `ctx_fixed_notokens`: ablations of ctx_fixed without the project-size / sdk-version
  context columns, and without code tokens.
- `ctx_pairs`: ctx_fixed with the fixed versions of real vulnerabilities upweighted (x1 / x3 / x10) and code tokens
  on or off, picked on inner folds.
- `v1_recipe_nomut` / `ctx_nomut`: v1_recipe / ctx_fixed with mutation rows at weight 0 (real rows, their fixed
  versions, mutation originals and corpus only).
- `ctx_search`: the v2 features with hyperparameters picked on inner group folds (eval_common.selection_score):
  learning rate, leaves, depth, min leaf size, token features (0 / 500 / 1000), label-1 class weight, and the
  real-vs-mutation weight ratio.

    uv run python -m near.model.train_classic_v2                     # all candidates, full train_v2
    uv run python -m near.model.train_classic_v2 --small --candidates v1_recipe,ctx_fixed
    uv run python -m near.model.train_classic_v2 --rescore           # metrics/markdown from saved OOF scores
    uv run python -m near.model.train_classic_v2 --candidates "" --final ctx_fixed_noera   # freeze input only
    NEAR_V2_CACHE=/some/dir uv run python -m near.model.train_classic_v2 ...                 # cache the features

Inference with the same features: `matrices_for_source(files, fns)` (needs the files dict that
predict.score_source has).
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import pickle
import time
from collections import Counter, defaultdict
from multiprocessing import get_context

import numpy as np
import scipy.sparse as sp
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_selection import SelectKBest, chi2
from threadpoolctl import threadpool_limits

from near.analyzer import features as analyzer_features
from near.analyzer.features import FEATURE_KEYS
from near.collect.extract_corpus import is_trivial
from near.model import context as cx
from near.model import eval_common as ec
from near.model import featurize as fz

DATA = "near/data"
REPORTS = "near/model/reports"
OUT = f"{REPORTS}/classic_v2_cv"
REPOS_DIR = "near/data/raw/repos"
CACHE_DIR = os.environ.get("NEAR_V2_CACHE")  # opt-in feature cache directory (about 150 MB for train_v2)
V1_PARAMS = {"lr": 0.1, "leaves": 31, "iters": 300, "l2": 1.0, "top_tokens": 1000, "depth": None, "min_leaf": 20,
             "pos": 1.0, "r2m": 1.0}
BLOCKS = {"v1": ("A0", "T"), "file": ("A1", "T"), "file_det": ("A1", "D", "T"), "v2": ("A1", "D", "X", "T"), "v2_noera": ("A1", "D", "Xn", "T")}
ERA_KEYS = ("ctx_sdk_version", "ctx_crate_fns", "ctx_crate_lines", "ctx_file_fns")  # which project / era, not the bug
_G: dict = {}  # rows, matrices and labels shared with forked workers


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def search_grid(n: int = 12, seed: int = ec.SEED) -> list[dict]:
    """v1 params (on v2 features) first, then n configs drawn without replacement from the product grid."""
    space = list(itertools.product((0.05, 0.1), (15, 31, 63), (None, 8), (20, 80), (0, 500, 1000), (1.0, 2.0),
                                   (1.0, 3.0)))
    pick = np.random.RandomState(seed).choice(len(space), n, replace=False)
    out = [dict(V1_PARAMS)]
    for i in sorted(pick):
        lr, leaves, depth, ml, tok, pos, r2m = space[i]
        out.append({"lr": lr, "leaves": leaves, "iters": 500 if lr == 0.05 else 300, "l2": 1.0, "top_tokens": tok,
                    "depth": depth, "min_leaf": ml, "pos": pos, "r2m": r2m})
    return out


CANDIDATES = {  # name -> (feature blocks, weight scheme, grid)
    "v1_recipe": ("v1", "v2", [dict(V1_PARAMS)]),
    "v1_recipe_v1w": ("v1", "v1", [dict(V1_PARAMS)]),
    "file_only": ("file", "v2", [dict(V1_PARAMS)]),
    "file_det": ("file_det", "v2", [dict(V1_PARAMS)]),
    "ctx_fixed": ("v2", "v2", [dict(V1_PARAMS)]),
    "ctx_fixed_noera": ("v2_noera", "v2", [dict(V1_PARAMS)]),
    "ctx_fixed_notokens": ("v2", "v2", [dict(V1_PARAMS, top_tokens=0)]),
    "ctx_search": ("v2", "v2", search_grid()),
    "v1_recipe_nomut": ("v1", "v2", [dict(V1_PARAMS, mut=0.0)]),
    "ctx_nomut": ("v2", "v2", [dict(V1_PARAMS, mut=0.0)]),
    "ctx_pairs": ("v2", "v2", [dict(V1_PARAMS, top_tokens=t, fixed=f) for t in (1000, 0) for f in (1.0, 3.0, 10.0)]),
}


# --- data -------------------------------------------------------------------------------------------------------
def load_train(path: str) -> tuple[list[dict], dict]:
    if "test" in os.path.basename(path):
        raise SystemExit("refusing to read a test file in the training stage")
    with open(path) as f:
        rows = [json.loads(line) for line in f]
    return rows, {"train_file": path, "train_sha256": sha256(path), "n_raw": len(rows)}


def repo_dir(r: dict, repos_dir: str = REPOS_DIR) -> str | None:
    name = r.get("fetched_from")
    if not name:
        url = (r.get("repo") or "").rstrip("/")
        if "github.com/" not in url:
            return None
        name = "__".join(url.split("github.com/", 1)[1].split("/")[:2])
    d = os.path.join(repos_dir, name)
    return d if os.path.isdir(d) else None


def _feature_vectors(fn: dict, path: str, files, cache) -> tuple[list[float], list[float], list[float], bool]:
    c = cx.row_context(fn, path, files, cache)
    a = analyzer_features(fn, c["file_src"])
    return ([a[k] for k in FEATURE_KEYS], [c["detectors"][k] for k in cx.DETECTOR_KEYS],
            [c["context"][k] for k in cx.CONTEXT_KEYS], c["available"])


def _ctx_job(job):
    """One (clone, commit): read the union of the rows' scope files once, then featurize every row."""
    d, commit, items = job
    out, stats = [], Counter()
    listing = cx.git_listing(d, commit) if d and commit else None
    files = None
    if listing:
        keys = set(listing)
        want = sorted({p for _, _, path in items if path in keys for p in cx.scope_paths(listing, path)})
        files = cx.git_read(d, commit, want)
        miss_toml = [p for p in want if p.endswith("Cargo.toml") and p not in files]
        if miss_toml:  # partial clone: manifests of old commits may be absent; use HEAD's (crate facts rarely move)
            head = cx.git_read(d, "HEAD", miss_toml)
            files.update(head)
            stats["cargo_toml_from_head"] += len(head)
        stats["scope_files_missing"] += sum(1 for p in want if p not in files)
    cache: dict = {}
    for idx, fn, path in items:
        a, det, x, ok = _feature_vectors(fn, path, files if files and path in files else None, cache)
        stats["available" if ok else "fn_only"] += 1
        out.append((idx, a, det, x, ok))
    return out, stats


def context_matrices(rows: list[dict], workers: int = 16) -> tuple:
    """(analyzer features with the file, per-detector counts, context features, file available per row, stats);
    counts signed-log scaled."""
    jobs = defaultdict(list)
    for i, r in enumerate(rows):
        jobs[(repo_dir(r), r.get("commit"))].append((i, cx.fn_record(r), r.get("path") or ""))
    jl = sorted(((d, c, it) for (d, c), it in jobs.items()), key=lambda j: -len(j[2]))
    if workers > 1:
        with get_context("fork").Pool(workers) as pool:
            res = pool.map(_ctx_job, jl, chunksize=1)
    else:
        res = list(map(_ctx_job, jl))
    A = np.zeros((len(rows), len(FEATURE_KEYS)))
    D = np.zeros((len(rows), len(cx.DETECTOR_KEYS)))
    X = np.zeros((len(rows), len(cx.CONTEXT_KEYS)))
    avail = np.zeros(len(rows), bool)
    stats = Counter()
    for out, st in res:
        stats.update(st)
        for idx, a, det, x, ok in out:
            A[idx], D[idx], X[idx], avail[idx] = a, det, x, ok
    return _slog(A), _slog(D), X.astype(np.float32), avail, dict(stats)


def with_derived(M: dict) -> dict:
    """Adds Xn: the context block without the project-size / sdk-version columns (ERA_KEYS)."""
    keep = [j for j, k in enumerate(cx.CONTEXT_KEYS) if k not in ERA_KEYS]
    return dict(M, Xn=M["X"][:, keep])


def _slog(M):
    return (np.sign(M) * np.log1p(np.abs(M))).astype(np.float32)


def token_matrix(rows: list[dict], workers: int = 16, chunk: int = 1000):
    slim = [{k: r.get(k) for k in ("code", "attrs", "is_near_bindgen", "is_public", "trait", "is_payable")}
            for r in rows]
    chunks = [slim[i:i + chunk] for i in range(0, len(slim), chunk)]
    if workers > 1:
        with get_context("fork").Pool(workers) as pool:
            parts = pool.map(fz._tok_chunk, chunks, chunksize=1)
    else:
        parts = list(map(fz._tok_chunk, chunks))
    return sp.vstack(parts).tocsr()


def featurize(rows: list[dict], workers: int = 16, cache_key: str | None = None) -> dict:
    """{A0, A1, D, X, T, available, stats}; cached under $NEAR_V2_CACHE (when set) by (train sha, context / featurize / analyzer code sha).
    The row loop (_ctx_job) is in this file and not in the key: clear the cache after changing it."""
    path = None
    if cache_key and CACHE_DIR:
        code = "".join(sha256(f) for f in ("near/model/context.py", "near/model/featurize.py",
                                           "near/analyzer/detectors.py", "near/analyzer/features.py",
                                           "near/analyzer/rust_parse.py"))
        path = os.path.join(CACHE_DIR, f"v2feat_{hashlib.sha256((cache_key + code).encode()).hexdigest()[:16]}.pkl")
        if os.path.exists(path):
            fz.fill_context(rows)
            with open(path, "rb") as f:
                return pickle.load(f)
    fz.fill_context(rows)
    A0 = fz.analyzer_matrix(rows, workers).astype(np.float32)
    A1, D, X, avail, stats = context_matrices(rows, workers)
    T = token_matrix(rows, workers)
    out = {"A0": A0, "A1": A1, "D": D, "X": X, "T": T, "available": avail, "stats": stats,
           "context_from": dict(Counter(r["context_from"] for r in rows))}
    if path:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(out, f)
    return out


def matrices_for_source(files: dict[str, str], fns: list[dict]) -> dict:
    """Inference: the v2 blocks for extracted functions (records with `path`) of one source tree, built by the same
    code as training (context over the scope files of each function's crate)."""
    cache: dict = {}
    A, D, X = [], [], []
    for f in fns:
        a, d, x, _ = _feature_vectors(cx.fn_record(f), f.get("path") or "", files, cache)
        A.append(a), D.append(d), X.append(x)
    T = fz.TOKEN_HASH.transform([fz.token_ngrams(f) for f in fns]).astype(np.float32)
    return with_derived({"A1": _slog(np.array(A, float).reshape(-1, len(FEATURE_KEYS))),
                         "D": _slog(np.array(D, float).reshape(-1, len(cx.DETECTOR_KEYS))),
                         "X": np.array(X, np.float32).reshape(-1, len(cx.CONTEXT_KEYS)), "T": T})


# --- weights and model ------------------------------------------------------------------------------------------
def weights(rows: list[dict], p: dict, scheme: str = "v2") -> np.ndarray:
    """Protocol weights (eval_common.sample_weights; info rows at 0.3 as in v1, none left in train_v2), real-vs-mutation
    ratio p["r2m"], label-1 rows times p["pos"], real label-0 rows times p["fixed"], mutations times p["mut"]. scheme v1 = pre-relabel
    `weight_v1` where present."""
    if scheme == "v1":
        rows = [dict(r, weight=r["weight_v1"]) if "weight_v1" in r else r for r in rows]
    w = ec.sample_weights(rows, real_to_mutation=p.get("r2m", 1.0), info_weight=0.3)
    w[np.array([r["label"] == 1 for r in rows])] *= p.get("pos", 1.0)
    if p.get("mut", 1.0) != 1.0:  # mutation rows times p["mut"] (0 = real data and corpus only)
        w[np.array([r["source"] == "mutation" for r in rows])] *= p["mut"]
    if p.get("fixed", 1.0) != 1.0:  # real label-0 rows (the fixed versions): the only negatives that differ by the bug
        w[np.array([ec.is_real(r) and r["label"] == 0 for r in rows])] *= p["fixed"]
    return w


def fit_model(p: dict, blocks: tuple, M: dict, y, w, seed: int = ec.SEED) -> dict:
    m = {"params": p, "blocks": blocks}
    if p.get("top_tokens"):
        m["tokens"] = SelectKBest(chi2, k=p["top_tokens"]).fit(M["T"], y).get_support(indices=True)
    clf = HistGradientBoostingClassifier(learning_rate=p["lr"], max_leaf_nodes=p["leaves"], max_iter=p["iters"],
                                         l2_regularization=p["l2"], max_depth=p.get("depth"),
                                         min_samples_leaf=p.get("min_leaf", 20), early_stopping=False,
                                         random_state=seed)
    m["clf"] = clf.fit(design(m, M), y, sample_weight=w)
    return m


def design(m: dict, M: dict) -> np.ndarray:
    parts = [M[b] for b in m["blocks"] if b != "T"]
    if "tokens" in m:
        parts.append((M["T"][:, m["tokens"]] > 0).toarray().astype(np.float32))
    return np.hstack(parts)


def predict_model(m: dict, M: dict) -> np.ndarray:
    return m["clf"].predict_proba(design(m, M))[:, 1]


def _sub(M: dict, idx) -> dict:
    return {k: M[k][idx] for k in M}


def _fit_score(job):
    name, gi, tr, te = job
    blocks_key, scheme, grid = CANDIDATES[name]
    p, blocks = grid[gi], BLOCKS[blocks_key]
    rows, M, y = _G["rows"], _G["M"], _G["y"]
    m = fit_model(p, blocks, _sub(M, tr), y[tr], weights([rows[i] for i in tr], p, scheme))
    return predict_model(m, _sub(M, te))


def _limit_threads(n: int = 1):
    threadpool_limits(n)


def run_jobs(jobs, workers):
    """Each fit in a forked child (libomp is not fork-safe once the parent starts OpenMP threads)."""
    if workers <= 0:
        return [_fit_score(j) for j in jobs]
    with get_context("fork").Pool(min(workers, len(jobs)), initializer=_limit_threads) as pool:
        return pool.map(_fit_score, jobs, chunksize=1)


# --- nested CV ----------------------------------------------------------------------------------------------------
def nested(name: str, rows: list[dict], outer: int, inner: int, seed: int, workers: int, log=print) -> dict:
    """eval_common.nested_group_cv semantics (same outer / inner folds), with every fit of every fold submitted to
    one pool: inner grid -> best params by selection_score -> outer fit; thresholds from the chosen inner OOF."""
    grid = CANDIDATES[name][2]
    n = len(rows)
    folds = ec.group_folds(rows, outer, seed)
    inner_folds = []
    for f, (tr, _) in enumerate(folds):
        sub = [rows[i] for i in tr]
        inner_folds.append([(tr[a], tr[b]) for a, b in ec.group_folds(sub, inner, seed + 1 + f)])
    jobs = [(name, gi, itr, ite) for f in range(outer) for gi in range(len(grid)) for itr, ite in inner_folds[f]]
    single = len(grid) == 1
    if single:  # no selection needed: outer fits go in the same batch
        jobs += [(name, 0, tr, te) for tr, te in folds]
    t0 = time.time()
    preds = run_jobs(jobs, workers)
    log(f"  {name}: {len(jobs)} fits in {time.time() - t0:.0f}s")
    k = 0
    chosen, oofs, tables = [], [], []
    for f, (tr, te) in enumerate(folds):
        pos = {int(i): j for j, i in enumerate(tr)}
        sub = [rows[i] for i in tr]
        table = []
        for gi in range(len(grid)):
            oof = np.full(len(tr), np.nan)
            for itr, ite in inner_folds[f]:
                oof[[pos[int(i)] for i in ite]] = preds[k]
                k += 1
            table.append((ec.selection_score(sub, oof), gi, oof))
        best = max(table, key=lambda t: (t[0], -t[1]))
        chosen.append(best[1])
        oofs.append(best[2])
        tables.append([(gi, round(s, 4)) for s, gi, _ in table])
    if single:
        outer_preds = preds[k:]
    else:
        outer_preds = run_jobs([(name, chosen[f], tr, te) for f, (tr, te) in enumerate(folds)], workers)
    scores, fold_of = np.full(n, np.nan), np.full(n, -1)
    decisions = {lvl: np.zeros(n, bool) for lvl in ec.LEVELS}
    thresholds = {lvl: [] for lvl in ec.LEVELS}
    for f, (tr, te) in enumerate(folds):
        thr = ec.thresholds_from([rows[i] for i in tr], oofs[f])
        s = np.asarray(outer_preds[f], float)
        scores[te], fold_of[te] = s, f
        for lvl, t in thr.items():
            thresholds[lvl].append(t)
            decisions[lvl][te] = s >= t
        log(f"  outer fold {f}: train {len(tr)} test {len(te)} thresholds "
            + " ".join(f"{a}={b:.4g}" for a, b in thr.items()) + f" params {grid[chosen[f]]}"
            + ("" if single else f" grid {tables[f]}"))
    return {"scores": scores, "decisions": decisions, "thresholds": thresholds, "fold": fold_of,
            "params": [grid[c] for c in chosen], "grid_tables": tables, "seconds": round(time.time() - t0)}


def final_selection(name: str, rows: list[dict], inner: int, seed: int, workers: int) -> dict:
    """Params for a freeze: the inner grid run over all (non-trivial) train with folds seed + 100, as v1."""
    grid = CANDIDATES[name][2]
    folds = ec.group_folds(rows, inner, seed + 100)
    preds = run_jobs([(name, gi, tr, te) for gi in range(len(grid)) for tr, te in folds], workers)
    table, k = [], 0
    for gi in range(len(grid)):
        oof = np.full(len(rows), np.nan)
        for _, te in folds:
            oof[te] = preds[k]
            k += 1
        table.append((ec.selection_score(rows, oof), gi, oof))
    best = max(table, key=lambda t: (t[0], -t[1]))
    return {"params": grid[best[1]], "oof": best[2], "oof_thresholds": ec.thresholds_from(rows, best[2]),
            "grid": [(gi, round(s, 4)) for s, gi, _ in table]}


# --- metrics --------------------------------------------------------------------------------------------------------
def bucket(r: dict) -> str | None:
    """Real label-1 evidence bucket: relabel verdict (confirmed / plausible) or, for new fix-commit rows, triage
    confidence."""
    if not ec.is_real(r) or r["label"] != 1:
        return None
    if r.get("relabel_verdict"):
        return r["relabel_verdict"]
    return f"fix_commit_v2_{r.get('confidence') or 'unknown'}"


def extra_metrics(rows: list[dict], s: np.ndarray, decisions: dict) -> dict:
    """Recall per evidence bucket and per real source, weight-weighted recall, pair ranking per source."""
    b = np.array([bucket(r) for r in rows], object)
    src = np.array([r["source"] for r in rows])
    real_pos = np.array([ec.is_real(r) and r["label"] == 1 for r in rows])
    w = np.array([float(r.get("weight") or 1.0) for r in rows])
    out = {"buckets": {}, "sources": {}, "weighted_recall": {}, "pair_rank_by_source": {}}
    for lvl, hit in decisions.items():
        out["buckets"][lvl] = {k: ec.rate(hit, b == k) for k in sorted(set(b[real_pos]))}
        out["sources"][lvl] = {k: ec.rate(hit, real_pos & (src == k)) for k in sorted(set(src[real_pos]))}
        out["weighted_recall"][lvl] = float((w * hit)[real_pos].sum() / w[real_pos].sum())
    for k in sorted(set(src[real_pos])):
        keep = [i for i, r in enumerate(rows) if r["source"] == k]
        out["pair_rank_by_source"][k] = ec.pair_rank([rows[i] for i in keep], s[keep])
    neg = ec.calibration_negatives(rows)
    mut = np.array([r["source"] == "mutation" and r["label"] == 1 for r in rows])
    out["pooled"] = {}
    for lvl, t in ec.thresholds_from(rows, s).items():
        hit = s >= t
        out["pooled"][lvl] = {"threshold": t, "recall_real": ec.rate(hit, real_pos), "recall_mutation": ec.rate(hit, mut),
                              "fpr_corpus_contract": ec.rate(hit, neg),
                              "buckets": {k: ec.rate(hit, b == k) for k in sorted(set(b[real_pos]))}}
    out["pair_rank_same_length"] = pair_rank_same_length(rows, s)
    out["pair_rank_shorter_baseline"] = ec.pair_rank(rows, -np.array([r["code"].count("\n") for r in rows], float))
    return out


def pair_rank_same_length(rows: list[dict], s: np.ndarray) -> dict:
    """Pair rank over real pairs whose two versions have the same number of lines. Fixes usually add lines, and
    "shorter = vulnerable" alone ranks most pairs right (pair_rank_shorter_baseline), so this subset shows whether
    a model ranks the pair by more than length."""
    pos = {r["id"]: i for i, r in enumerate(rows)}
    keep = set()
    for i, r in enumerate(rows):
        j = pos.get(r.get("pair_id"))
        if ec.is_real(r) and r["label"] == 1 and j is not None and rows[j]["label"] == 0 \
                and r["code"].count("\n") == rows[j]["code"].count("\n"):
            keep.update((i, j))
    keep = sorted(keep)
    return ec.pair_rank([rows[i] for i in keep], s[keep])


def full_metrics(rows_all: list[dict], scored: np.ndarray, s_sub: np.ndarray, dec_sub: dict) -> tuple:
    """Scores over all train rows with trivial functions at -1 (never alarm), as the deployed rule."""
    s = np.full(len(rows_all), -1.0)
    s[scored] = s_sub
    dec = {lvl: np.zeros(len(rows_all), bool) for lvl in ec.LEVELS}
    for lvl in ec.LEVELS:
        dec[lvl][scored] = dec_sub[lvl]
    return s, dec, ec.metrics(rows_all, s, dec), extra_metrics(rows_all, s, dec)


def paired_diff(rows: list[dict], a: tuple, b: tuple, n_boot: int = 2000, seed: int = ec.SEED) -> dict:
    """Candidate b minus baseline a on the same rows: real recall (block, warn), mutation recall (warn) and pair rank,
    with 95% intervals from a bootstrap over groups (rows of a group resampled together)."""
    (sa, da), (sb, db) = a, b
    groups = sorted({r["group"] for r in rows})
    gi = {g: i for i, g in enumerate(groups)}
    g = np.array([gi[r["group"]] for r in rows])
    rp = np.array([ec.is_real(r) and r["label"] == 1 for r in rows])
    mut = np.array([r["source"] == "mutation" and r["label"] == 1 for r in rows])
    pos = {r["id"]: i for i, r in enumerate(rows)}
    pairs = [(i, pos[r["pair_id"]]) for i, r in enumerate(rows) if rp[i] and r.get("pair_id") in pos
             and rows[pos[r["pair_id"]]]["label"] == 0]
    pi, pj = np.array([p[0] for p in pairs], int), np.array([p[1] for p in pairs], int)

    def win(s):
        return np.where(s[pi] > s[pj], 1.0, np.where(s[pi] == s[pj], 0.5, 0.0))

    stats = {"block_real": (rp, db["block"].astype(float) - da["block"]),
             "warn_real": (rp, db["warn"].astype(float) - da["warn"]),
             "warn_mutation": (mut, db["warn"].astype(float) - da["warn"])}
    per = {k: (np.bincount(g[m], d[m], len(groups)), np.bincount(g[m], minlength=len(groups)))
           for k, (m, d) in stats.items()}
    per["pair_rank"] = (np.bincount(g[pi], win(sb) - win(sa), len(groups)), np.bincount(g[pi], minlength=len(groups)))
    rng = np.random.RandomState(seed)
    boot = rng.randint(0, len(groups), (n_boot, len(groups)))
    out = {}
    for k, (num, den) in per.items():
        est = num.sum() / max(den.sum(), 1)
        bs = num[boot].sum(1) / np.maximum(den[boot].sum(1), 1)
        out[k] = {"diff": float(est), "lo": float(np.percentile(bs, 2.5)), "hi": float(np.percentile(bs, 97.5)),
                  "n": int(den.sum())}
    return out


def _jsonable(o):
    if isinstance(o, dict):
        return {str(k): _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsonable(v) for v in o]
    if isinstance(o, (np.floating, float)):
        return None if not np.isfinite(o) else float(o)
    if isinstance(o, (np.integer, np.bool_)):
        return o.item()
    return o


# --- report ---------------------------------------------------------------------------------------------------------
def _f(d) -> str:
    return ec.fmt_rate(d) if d and d.get("n") else "n/a"


def _x(v, nd=3) -> str:
    return "n/a" if v is None else f"{v:.{nd}f}"


def _thr(c: dict, lvl: str) -> str:
    t = [x for x in c.get("fold_thresholds", {}).get(lvl, []) if x is not None]
    return f"median {np.median(t):.4f} ({min(t):.4f}-{max(t):.4f})" if t else "n/a"


def render_md(rep: dict) -> str:
    d, pr = rep["data"], rep["protocol"]
    o = ["# Classical v2: nested grouped CV on train_v2 (NEAR code risk)", "",
         f"Data: `{d['train_file']}` sha256 `{d['train_sha256'][:16]}...`, {d['n_raw']} rows, minus "
         f"{d['no_file_rows_excluded']['n']} rows whose source file is not in the local clones "
         f"({d['no_file_rows_excluded']['by']}; excluded from every candidate, see Notes), "
         f"{d['n_raw'] - d['no_file_rows_excluded']['n']} evaluated ({d['n_scored']} "
         f"non-trivial rows fitted and scored; {d['n_raw'] - d['no_file_rows_excluded']['n'] - d['n_scored']} trivial rows never alarm, as the "
         "deployed rule). Split-audit drops and relabels are already applied in train_v2; no sealed test file was "
         f"read. Outer {pr['outer']}-fold / inner {pr['inner']}-fold GroupKFold over `group`, seed {pr['seed']} (the "
         "folds of eval_common.nested_group_cv). Thresholds per outer fold come from the chosen config's inner OOF "
         "scores: block = 1%, warn = 5% FPR on contract-code corpus negatives. Rates are pooled over outer folds, "
         "with Wilson 95% CIs.", "",
         f"Context availability (rows): {rep['feature_stats']}. Function-level `fill_context`: {rep['context_from']}.",
         "", f"Selection objective (inner folds): {' '.join(pr['selection'].split())}", "",
         "## Protocol table", "",
         "| candidate | PR-AUC | ROC-AUC | ROC real vs contract corpus | ROC real vs fixed | pair rank (vuln > fixed) | "
         "block: real recall | warn: real recall | block: mutation | warn: mutation | block FPR contract | "
         "warn FPR contract | warn FPR fixed |", "|" + "---|" * 13]
    for name, c in rep["candidates"].items():
        m = c["metrics"]
        o.append(f"| {name} | {_x(m['pr_auc'])} | {_x(m['roc_auc'])} | {_x(m['roc_auc_real_vs_contract_corpus'])} | "
                 f"{_x(m['roc_auc_real_vs_fixed'])} | {_f(m['pair_rank_acc'])} | {_f(m['block']['recall_real'])} | "
                 f"{_f(m['warn']['recall_real'])} | {_f(m['block']['recall_mutation'])} | "
                 f"{_f(m['warn']['recall_mutation'])} | {_f(m['block']['fpr_corpus_contract'])} | "
                 f"{_f(m['warn']['fpr_corpus_contract'])} | {_f(m['warn']['fpr_paired_fixed'])} |")
    o += ["", "Real recall by evidence: relabel verdict confirmed / plausible on the v1 positives, triage confidence "
          "on the new v2 fix-commit positives. Weighted recall uses the `weight` field.", "",
          "| candidate | level | confirmed | plausible | fix_commit v2 high | fix_commit v2 medium | weighted recall |",
          "|---|---|---|---|---|---|---|"]
    for name, c in rep["candidates"].items():
        e = c["extra"]
        for lvl in ec.LEVELS:
            bk = e["buckets"][lvl]
            o.append(f"| {name} | {lvl} | {_f(bk.get('confirmed'))} | {_f(bk.get('plausible'))} | "
                     f"{_f(bk.get('fix_commit_v2_high'))} | {_f(bk.get('fix_commit_v2_medium'))} | "
                     f"{100 * e['weighted_recall'][lvl]:.1f}% |")
    o += ["", "Recall at pooled thresholds: the threshold is set on the pooled outer OOF scores themselves, so every "
          "candidate sits at exactly 1% / 5% contract-corpus FPR. This is optimistic but fair across candidates whose "
          "nested thresholds miss the target FPR (as the no-mutation ones do).", "",
          "| candidate | block: real | block: confirmed | warn: real | warn: confirmed | warn: mutation |",
          "|---|---|---|---|---|---|"]
    for name, c in rep["candidates"].items():
        p = c["extra"].get("pooled")
        if p:
            o.append(f"| {name} | {_f(p['block']['recall_real'])} | {_f(p['block']['buckets'].get('confirmed'))} | "
                     f"{_f(p['warn']['recall_real'])} | {_f(p['warn']['buckets'].get('confirmed'))} | "
                     f"{_f(p['warn']['recall_mutation'])} |")
    o += ["", "Pair rank controls: the length-only score (shorter = more vulnerable) ranks "
          + _f(next(iter(rep["candidates"].values()))["extra"].get("pair_rank_shorter_baseline"))
          + " of real pairs, because fixes usually add lines. On pairs of equal length:", "",
          "| candidate | pair rank, equal-length pairs |", "|---|---|"]
    o += [f"| {name} | {_f(c['extra'].get('pair_rank_same_length'))} |" for name, c in rep["candidates"].items()]
    o += ["", "| candidate | level | audit | fix_commit | incident | pair rank audit | pair rank fix_commit | "
          "contract: clean files alarming | contract: vulnerable files alarming |", "|---|---|---|---|---|---|---|---|---|"]
    for name, c in rep["candidates"].items():
        e, m = c["extra"], c["metrics"]
        for lvl in ec.LEVELS:
            s = e["sources"][lvl]
            o.append(f"| {name} | {lvl} | {_f(s.get('audit'))} | {_f(s.get('fix_commit'))} | {_f(s.get('incident'))} | "
                     f"{_f(e['pair_rank_by_source'].get('audit'))} | {_f(e['pair_rank_by_source'].get('fix_commit'))} | "
                     f"{_f(m[lvl]['contract_alarm_share'])} | {_f(m[lvl]['contract_recall_real'])} |")
    o.append("")
    for name, c in rep["candidates"].items():
        m = c["metrics"]
        o += [f"## {name}", "", f"Feature blocks {c['blocks']}, weights `{c['weights']}`, {c['seconds']}s. "
              f"Params per outer fold: {c['fold_params']}.", "", "| | block (FPR 1%) | warn (FPR 5%) |", "|---|---|---|",
              f"| threshold | {_thr(c, 'block')} | {_thr(c, 'warn')} |"]
        for label, k in (("recall, real label-1", "recall_real"), ("recall, mutations", "recall_mutation"),
                         ("false alarms, corpus negatives (all)", "fpr_corpus"),
                         ("false alarms, contract-code corpus", "fpr_corpus_contract"),
                         ("false alarms, paired fixed versions", "fpr_paired_fixed"),
                         ("false alarms, mutation originals", "fpr_mutation_original")):
            o.append(f"| {label} | {_f(m['block'][k])} | {_f(m['warn'][k])} |")
        o += ["", "| class (real) | block | warn |", "|---|---|---|"]
        o += [f"| {k} | {_f(v)} | {_f(m['warn']['recall_class_real'][k])} |"
              for k, v in m["block"]["recall_class_real"].items()]
        if c.get("grid_tables") and len(c["grid_tables"][0]) > 1:
            o += ["", "Inner selection scores per outer fold (grid index, score): "
                  + "; ".join(str(t) for t in c["grid_tables"]), "", "Grid: "
                  + "; ".join(f"{i}: {p}" for i, p in enumerate(CANDIDATES[name][2]))]
        o.append("")
    for name, f in rep.get("final_selection", {}).items():
        o += [f"## Freeze input: all-train selection for {name}", "", f"Params {f['params']}; thresholds from grouped "
              "3-fold OOF scores on all non-trivial train rows: "
              + ", ".join(f"{k} {v:.4f}" for k, v in f["oof_thresholds"].items()) + f". Grid scores {f['grid']}.", ""]
    if rep.get("comparison", {}).get("pooled"):
        o += ["## Difference from v1_recipe (same rows, same folds)", "",
              "Candidate minus v1_recipe, in percentage points, with a 95% interval from a bootstrap over groups. "
              "`nested` = alarms at the nested thresholds (the protocol numbers); `pooled` = alarms at thresholds set "
              "on each candidate's pooled OOF scores (exactly 1% / 5% contract-corpus FPR for every candidate).", "",
              "| candidate | thresholds | block: real recall | warn: real recall | warn: mutation recall | pair rank |",
              "|---|---|---|---|---|---|"]
        for name in rep["comparison"]["pooled"]:
            for kind in ("nested", "pooled"):
                c = rep["comparison"][kind][name]
                o.append(f"| {name} | {kind} | " + " | ".join(
                    f"{100 * c[k]['diff']:+.1f} [{100 * c[k]['lo']:+.1f}, {100 * c[k]['hi']:+.1f}]"
                    for k in ("block_real", "warn_real", "warn_mutation", "pair_rank")) + " |")
        o.append("")
    o += ["## Notes", "", rep.get("notes", NOTES)]
    return "\n".join(o) + "\n"


NOTES = """Findings:
- No v2 candidate detects more real vulnerabilities than the v1 recipe retrained on train_v2. At equal FPR (pooled
  thresholds) every candidate sits at 3-5% real recall at block and 13-17% at warn. The bootstrap differences against
  v1_recipe all include 0. This holds for the cleaned weights (v1_recipe vs v1_recipe_v1w), the file context, the
  per-detector counts, upweighting the fixed versions, and the hyperparameter search.
- File context and per-detector counts do raise recall on mutations, by about 8 points at warn (CI excludes 0). They
  mostly help on the injected patterns: a removed owner check or #[private], in a file whose siblings keep theirs.
- Without mutations in training (`*_nomut`), the nested thresholds miss their target. Contract-corpus FPR comes out
  at 2.1-2.6% / 11.6-12.4% instead of 1% / 5%, so those rows' protocol recall is not comparable. At pooled
  thresholds their real recall is no higher, and mutation recall falls to about 11%.
- Pair ranking stays at chance (49-55%; 47-59% on the 67 equal-length pairs). A score that only says "shorter is more
  vulnerable" ranks 83.5% of real pairs right, because fixes add lines. A pairwise model trained on (mutation,
  original) differences ranked 80-85% of real pairs in a side experiment, and the length baseline explains it.
  None of the models here separates a vulnerable function from its fix by the bug.
- Real recall is higher on confirmed relabels and on high-confidence fix commits than on plausible / medium ones, at
  the same thresholds.

Protocol and data caveats:
- Leak checks changed the design during this work. A first run gave context features the whole crate, read from the
  partial local clones. ctx_fixed then reached block 12.4% / warn 26.1% real recall against 6.2% / 18.5% for
  v1_recipe. That gain was an artifact. 40% of real train rows (old commits) lack sibling .rs blobs offline, while no
  corpus or mutation row does. And the 47 audit positives with no file at all got a "function alone" context that
  only positives had: 39 of them alarmed at block, against 12 for v1_recipe. All numbers here come after both fixes:
  file-scope context, and those 47 rows (all audit positives) excluded from every candidate.
- train_v2 labels are cleaner than v1's but not verified: the relabel kept 64% of v1 train positives, and the 209 new
  fix-commit positives carry triage confidence only.
- These are CV numbers on train_v2. They are not comparable to v1's classic_cv (other rows and labels) and say nothing
  about test_v1c until a frozen model is scored once on it.
- Context comes from the local clone at the row's commit (offline). A Cargo.toml missing at an old commit is taken
  from HEAD. At inference the context is whatever `files` the service has; with no Cargo.toml the manifest features
  are -1, a value rare in training.
- Mutation rows get the context of their original function's file, which still holds the unmutated function. The
  function itself is excluded from its own sibling tables by name and path.
- Pair rank needs both members present: pairs whose partner was removed by the relabel are skipped."""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--small", action="store_true", help="train_v2_small.jsonl")
    ap.add_argument("--candidates", default=",".join(CANDIDATES))
    ap.add_argument("--outer", type=int, default=5)
    ap.add_argument("--inner", type=int, default=3)
    ap.add_argument("--seed", type=int, default=ec.SEED)
    ap.add_argument("--workers", type=int, default=17)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--sample-groups", type=int, default=0, help="smoke runs: keep only this many random groups")
    ap.add_argument("--final", default="", help="candidate to run the all-train selection for (freeze input)")
    ap.add_argument("--rescore", action="store_true")
    args = ap.parse_args()

    path = f"{DATA}/train_v2_small.jsonl" if args.small else f"{DATA}/train_v2.jsonl"
    rows_all, info = load_train(path)
    if args.sample_groups:
        keep = set(np.random.RandomState(0).permutation(sorted({r["group"] for r in rows_all}))[:args.sample_groups])
        rows_all = [r for r in rows_all if r["group"] in keep]
        info["sample_groups"] = args.sample_groups
    t0 = time.time()
    M_all = featurize(rows_all, args.workers, cache_key=f"{info['train_sha256']}|{args.sample_groups}")
    no_file = ~M_all["available"]  # only real positives lack their file: context would give them away (module doc)
    info["no_file_rows_excluded"] = {"n": int(no_file.sum()), "by": dict(Counter(
        f"{r['source']}:{r['label']}" for r, nf in zip(rows_all, no_file) if nf))}
    rows_all = [r for r, nf in zip(rows_all, no_file) if not nf]
    M_all = {k: (v[~no_file] if k in ("A0", "A1", "D", "X", "T") else v) for k, v in M_all.items()}
    scored = np.array([not is_trivial(r["code"]) for r in rows_all])
    idx = np.where(scored)[0]
    rows = [rows_all[i] for i in idx]
    M = with_derived({k: M_all[k][idx] for k in ("A0", "A1", "D", "X", "T")})
    y = np.array([r["label"] for r in rows])
    _G.update(rows=rows, M=M, y=y)
    info["n_scored"] = len(rows)
    print(f"{len(rows_all)} rows, {len(rows)} non-trivial, {int(y.sum())} label-1, {len({r['group'] for r in rows})} "
          f"groups; features in {time.time() - t0:.0f}s; context {M_all['stats']}", flush=True)

    rep_path = f"{args.out}.json"
    report = {"data": info, "protocol": {"outer": args.outer, "inner": args.inner, "seed": args.seed,
                                         "levels_fpr_on_contract_corpus": ec.LEVELS,
                                         "selection": ec.selection_score.__doc__.strip()},
              "feature_stats": M_all["stats"], "context_from": M_all["context_from"], "candidates": {}}
    if os.path.exists(rep_path):  # keep candidates from earlier runs of the same data and protocol
        with open(rep_path) as f:
            old = json.load(f)
        if old["data"]["train_sha256"] == info["train_sha256"] and old["protocol"]["seed"] == args.seed \
                and old["data"].get("sample_groups") == info.get("sample_groups"):
            report["candidates"] = old["candidates"]
            report["final_selection"] = old.get("final_selection", {})
    fold_of = np.full(len(rows_all), -1)
    for k, (_, te) in enumerate(ec.group_folds(rows, args.outer, args.seed)):
        fold_of[idx[te]] = k

    def saved(name):
        c = report["candidates"][name]
        s_all = np.load(f"{args.out}_{name}_oof.npy")
        return s_all, {lvl: scored & (s_all >= np.array([np.inf if t is None else t
                                                         for t in c["fold_thresholds"][lvl]])[fold_of])
                       for lvl in ec.LEVELS}

    if args.rescore:
        for name, c in report["candidates"].items():
            s_all, dec = saved(name)
            c["metrics"] = _jsonable(ec.metrics(rows_all, s_all, dec))
            c["extra"] = _jsonable(extra_metrics(rows_all, s_all, dec))
    for name in [c for c in args.candidates.split(",") if c] if not args.rescore else []:
        print(f"== {name}", flush=True)
        res = nested(name, rows, args.outer, args.inner, args.seed, args.workers,
                     log=lambda s: print(s, flush=True))
        s_all, dec, m, extra = full_metrics(rows_all, scored, res["scores"], res["decisions"])
        np.save(f"{args.out}_{name}_oof.npy", s_all)
        bk, sch, _ = CANDIDATES[name]
        report["candidates"][name] = _jsonable({
            "blocks": BLOCKS[bk], "weights": sch, "metrics": m, "extra": extra, "fold_thresholds": res["thresholds"],
            "fold_params": res["params"], "grid_tables": res["grid_tables"], "seconds": res["seconds"]})
        print(summary_line(name, m, extra), flush=True)
        _write(report, args.out)
    if args.final:
        print(f"== final selection on all train: {args.final}", flush=True)
        fin = final_selection(args.final, rows, args.inner, args.seed, args.workers)
        s_all = np.full(len(rows_all), -1.0)
        s_all[idx] = fin.pop("oof")
        np.save(f"{args.out}_final_{args.final}_oof.npy", s_all)
        report.setdefault("final_selection", {})[args.final] = _jsonable(fin)
    def pooled(name):
        s_all = saved(name)[0]
        return s_all, {lvl: s_all >= t for lvl, t in ec.thresholds_from(rows_all, s_all).items()}

    if "v1_recipe" in report["candidates"]:
        report["comparison"] = {
            kind: {name: _jsonable(paired_diff(rows_all, get("v1_recipe"), get(name)))
                   for name in report["candidates"] if name != "v1_recipe"}
            for kind, get in (("nested", saved), ("pooled", pooled))}
    _write(report, args.out)
    print(f"wrote {args.out}.json / .md")


def _write(report, out):
    with open(f"{out}.json", "w") as f:
        json.dump(_jsonable(report), f, indent=1)
    with open(f"{out}.md", "w") as f:
        f.write(render_md(report))


def summary_line(name: str, m: dict, e: dict) -> str:
    parts = [f"{name}: PR-AUC {m['pr_auc']:.3f} ROC-AUC {m['roc_auc']:.3f} real-vs-fixed ROC {m['roc_auc_real_vs_fixed']:.3f}"
             f" pair rank {ec.fmt_rate(m['pair_rank_acc'])}"]
    for lvl in ec.LEVELS:
        x = m[lvl]
        parts.append(f"{lvl}: real {ec.fmt_rate(x['recall_real'])} confirmed {_f(e['buckets'][lvl].get('confirmed'))} "
                     f"mut {ec.fmt_rate(x['recall_mutation'])} FPR-contract {ec.fmt_rate(x['fpr_corpus_contract'])}")
    return "\n  ".join(parts)


if __name__ == "__main__":
    main()
