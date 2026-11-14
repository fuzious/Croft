"""Merge real, corpus and mutation samples into the train set and the sealed test set (whole repositories per
split, so no group is in both).

Steps: signatures (norm_hash as in extract_corpus, identifier-renamed shape hash, token 5-gram MinHash), label
conflicts, group-level sealed test (seeded stratified share + post-2025 time split), per-split dedupe, removal of
train rows that copy or nearly copy a test row, a smaller train file for the encoder, manifest and report.

    uv run python -m near.collect.assemble   # -> near/data/{train_v1,train_v1_small,test_v1}.jsonl,
                                             #    split_manifest_v1.json, assembly_report.md
"""
from __future__ import annotations

import collections
import hashlib
import json
import random
import statistics
from multiprocessing import Pool
from pathlib import Path

import numpy as np

from near.analyzer.rust_parse import PARSER
from near.collect.extract_corpus import drop_reason, norm_code
from near.collect.resolve import ALIASES

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "near" / "data"
RAW = DATA / "raw"
SEED = 20261114
TEST_SHARE, TEST_CAP, SINCE = 0.25, 0.40, "2025-01-01"
SMALL_TARGET = 60_000
REAL = ("incident", "audit", "fix_commit")
SOURCE_RANK = {s: i for i, s in enumerate(REAL + ("mutation", "mutation_original", "corpus"))}
COMMENTS = {"line_comment", "block_comment"}
IDENTIFIERS = {"identifier", "field_identifier", "type_identifier", "shorthand_field_identifier", "metavariable"}
STRINGS = {"string_literal", "raw_string_literal", "char_literal"}
NUMBERS = {"integer_literal", "float_literal"}
SHINGLE, JACCARD_MIN = 5, 0.9
COPY_JACCARD, COPY_MIN_ROWS, COPY_MAX_GROUPS = 0.8, 3, 5  # copy repo: >= 3 rows of one real group at J >= 0.8
COPY_MIN_SHARE = 0.1  # two real groups join only if the copied rows are >= 10% of the smaller one's functions
SHAPE_MIN_TOKENS = 60  # shorter functions share shapes without being copies (guarded setters, counters)
N_PERM, BANDS = 128, 16  # 16 bands x 8 rows: a pair at Jaccard 0.9 becomes a candidate with p > 0.9999
PRIME = (1 << 31) - 1
_rng = np.random.default_rng(SEED)
PERM_A = _rng.integers(1, PRIME, N_PERM, dtype=np.uint64)
PERM_B = _rng.integers(0, PRIME, N_PERM, dtype=np.uint64)
TEMP = ("shingles", "minhash")


# ---------------------------------------------------------------- signatures
def tokens(code: str) -> list[tuple[str, str]]:
    """(node type, text) of the leaf tokens, comments skipped; a string/char literal is one token."""
    b = code.encode("utf8", errors="replace")
    out, stack = [], [PARSER.parse(b).root_node]
    while stack:
        n = stack.pop()
        if n.type in COMMENTS:
            continue
        if n.child_count == 0 or n.type in STRINGS:
            out.append((n.type, b[n.start_byte:n.end_byte].decode("utf8", errors="replace")))
        else:
            stack.extend(reversed(n.children))
    return out


def _h31(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode(), digest_size=4).digest(), "big") & PRIME


def minhash(shingles) -> np.ndarray:
    x = np.fromiter(shingles, dtype=np.uint64)
    return ((np.outer(x, PERM_A) + PERM_B) % PRIME).min(axis=0).astype(np.uint32)


def signatures(code: str) -> dict:
    """norm_hash (comments removed, whitespace collapsed, as extract_corpus), shape_hash (identifiers renamed
    consistently, literals replaced), token 5-gram shingles (string literals replaced) and their MinHash."""
    toks = tokens(code)
    names, shape, raw = {}, [], []
    for t, s in toks:
        if t in IDENTIFIERS:
            shape.append(f"${names.setdefault(s, len(names))}")
            raw.append(s)
        elif t in STRINGS:
            shape.append("S")
            raw.append("S")
        else:
            shape.append("N" if t in NUMBERS else s)
            raw.append(s)
    grams = [" ".join(raw[i:i + SHINGLE]) for i in range(max(1, len(raw) - SHINGLE + 1))]
    shingles = sorted({_h31(g) for g in grams})
    return {"norm_hash": hashlib.sha1(norm_code(code).encode()).hexdigest(),
            "shape_hash": hashlib.sha1(" ".join(shape).encode()).hexdigest(), "n_tokens": len(toks),
            "shingles": shingles, "minhash": minhash(shingles)}


def jaccard(a, b) -> float:
    a, b = set(a), set(b)
    return len(a & b) / len(a | b) if a or b else 1.0


# ---------------------------------------------------------------- merge rules
def canonical_group(g: str, aliases: dict, roots: dict) -> str:
    """Group of a corpus/mutation repo, mapped like the real rows: alias for a vanished original, else fork root."""
    k = g.lower()
    return aliases.get(k) or roots.get(k) or k


def _bands(m: np.ndarray) -> list[tuple]:
    r = N_PERM // BANDS
    return [(b, m[b * r:(b + 1) * r].tobytes()) for b in range(BANDS)]


def copy_groups(rows: list[dict]) -> dict:
    """{group: real group} for groups that copy a real-label project: at least COPY_MIN_ROWS distinct rows of one real
    group have a near-copy (token 5-gram Jaccard >= COPY_JACCARD) in the group. A non-real group joins the real group
    it copies most. Two real groups linked this way (either direction), with the copied rows at least COPY_MIN_SHARE of
    the smaller group's distinct functions, form one unit named after its member with the most real label-1 rows.
    Mutants are not counted. Real-group rows near-copied by more than COPY_MAX_GROUPS groups (templates, standard
    impls) do not count."""
    real = {r["group"] for r in rows if r["source"] in REAL}
    n_pos = collections.Counter(r["group"] for r in rows if r["source"] in REAL and r["label"] == 1)
    fns = collections.defaultdict(set)
    for r in rows:
        if r["source"] != "mutation":
            fns[r["group"]].add(r["norm_hash"])
    index = collections.defaultdict(list)
    for j, r in enumerate(rows):
        if r["group"] in real and r["source"] != "mutation":
            for k in _bands(r["minhash"]):
                index[k].append(j)
    hits = collections.defaultdict(set)  # real row -> other groups holding a near-copy
    for r in rows:
        if r["source"] == "mutation":
            continue
        cand = {j for k in _bands(r["minhash"]) for j in index.get(k, ())}
        for j in cand:
            if rows[j]["group"] != r["group"] and jaccard(r["shingles"], rows[j]["shingles"]) >= COPY_JACCARD:
                hits[j].add(r["group"])
    per = collections.defaultdict(collections.Counter)
    for j, groups in hits.items():
        if len(groups) <= COPY_MAX_GROUPS:
            for g in groups:
                per[g][rows[j]["group"]] += 1
    parent = {g: g for g in real}

    def find(g):
        while parent[g] != g:
            g = parent[g]
        return g

    for g, c in sorted(per.items()):
        if g in real:
            for rg, n in sorted(c.items()):
                if n >= COPY_MIN_ROWS and n >= COPY_MIN_SHARE * min(len(fns[g]), len(fns[rg])):
                    a, b = sorted((find(g), find(rg)), key=lambda x: (-n_pos[x], x))
                    parent[b] = a
    out = {g: find(g) for g in sorted(real) if find(g) != g}
    for g, c in sorted(per.items()):
        if g not in real:
            best, n = min(c.items(), key=lambda kv: (-kv[1], kv[0]))
            if n >= COPY_MIN_ROWS:
                out[g] = find(best)
    return out


def resolve_conflicts(rows: list[dict]) -> tuple[list[dict], collections.Counter]:
    """Corpus/mutation-original code identical to a real vulnerable function becomes label 1 (copied vulnerable code
    stays vulnerable); a real fixed row identical to a real vulnerable one is dropped; a mutant identical to any
    label-0 code is dropped."""
    st = collections.Counter()
    vuln = {}
    for r in sorted((r for r in rows if r["source"] in REAL and r["label"] == 1), key=lambda r: SOURCE_RANK[r["source"]]):
        vuln.setdefault(r["norm_hash"], r["vuln_class"])
    out = []
    for r in rows:
        if r["label"] == 0 and r["norm_hash"] in vuln:
            if r["source"] in REAL:
                st["dropped_real_fixed_same_as_vulnerable"] += 1
                continue
            r = {**r, "label": 1, "vuln_class": vuln[r["norm_hash"]], "relabeled_from_real": True}
            st["relabeled_from_real"] += 1
            st[f"relabeled_from_real_{r['source']}"] += 1
        out.append(r)
    safe = {r["norm_hash"] for r in out if r["label"] == 0}
    kept = []
    for r in out:
        if r["source"] == "mutation" and r["norm_hash"] in safe:
            st["dropped_mutant_same_as_label0"] += 1
            continue
        kept.append(r)
    return kept, st


def _dominant(values) -> str:
    c = collections.Counter(str(v) for v in values)
    return min(c.items(), key=lambda kv: (-kv[1], kv[0]))[0]


def pick_test_groups(rows: list[dict], seed: int = SEED, share: float = TEST_SHARE, cap: float = TEST_CAP,
                     since: str = SINCE) -> tuple[set, dict]:
    """Sealed-test groups: every group with an audit/incident row dated >= `since`, plus a seeded share of the other
    real-label groups, stratified by (dominant vuln_class, dominant source); the share shrinks so the test holds at
    most `cap` of the real-label groups and at most `cap` of the real label-1 rows."""
    pos = collections.defaultdict(list)
    for r in rows:
        if r["source"] in REAL and r["label"] == 1:
            pos[r["group"]].append(r)
    groups = sorted(pos)
    post = sorted({r["group"] for r in rows if r["source"] in ("audit", "incident") and (r.get("date") or "") >= since
                   and r["group"] in pos})
    rest = [g for g in groups if g not in set(post)]
    strata = collections.defaultdict(list)
    for g in rest:
        strata[(_dominant(r["vuln_class"] for r in pos[g]), _dominant(r["source"] for r in pos[g]))].append(g)
    rng = random.Random(seed)
    order, tiebreak = {}, {}
    for s in sorted(strata):
        order[s] = sorted(strata[s])
        rng.shuffle(order[s])
        tiebreak[s] = rng.random()

    def choose(k):
        exact = {s: k * len(order[s]) / len(rest) for s in order}
        quota = {s: int(v) for s, v in exact.items()}
        for s in sorted(exact, key=lambda s: (-(exact[s] - quota[s]), tiebreak[s]))[:k - sum(quota.values())]:
            quota[s] += 1
        return quota, sorted(g for s in order for g in order[s][:quota[s]])

    n_pos = sum(len(v) for v in pos.values())
    k = round(share * len(rest))
    quota, chosen = choose(k)
    while k > 0 and (len(post) + k > cap * len(groups) or
                     sum(len(pos[g]) for g in post + chosen) > cap * n_pos):
        k -= 1
        quota, chosen = choose(k)
    info = {"real_label_groups": len(groups), "time_split_groups": post, "random_groups": k,
            "random_group_list": chosen, "strata": {f"{a}|{b}": [len(order[(a, b)]), quota[(a, b)]] for a, b in order}}
    return set(post) | set(chosen), info


def dedupe(rows: list[dict]) -> tuple[list[dict], int]:
    """One row per (norm_hash, label), real sources first, then mutation, mutation_original, corpus."""
    seen, keep = set(), set()
    for i, r in sorted(enumerate(rows), key=lambda x: (SOURCE_RANK[x[1]["source"]], x[0])):
        k = (r["norm_hash"], r["label"])
        if k not in seen:
            seen.add(k)
            keep.add(i)
    return [r for i, r in enumerate(rows) if i in keep], len(rows) - len(keep)


def shape_targets(test: list[dict]) -> set:
    """shape_hash of the test real rows long enough for a shared shape to mean a renamed copy."""
    return {r["shape_hash"] for r in test if r["source"] in REAL and r["n_tokens"] >= SHAPE_MIN_TOKENS}


def remove_leaks(train: list[dict], test: list[dict]) -> tuple[list[dict], dict]:
    """Drop train rows that copy a test row: same norm_hash, same shape_hash as a test real row of >= 60 tokens, or
    token 5-gram Jaccard >= 0.9 (MinHash LSH candidates, verified exactly); then mutants whose original was dropped.
    Returns (kept, {id: reason})."""
    norm = {r["norm_hash"] for r in test}
    shape = shape_targets(test)
    index = collections.defaultdict(list)
    for j, r in enumerate(test):
        for k in _bands(r["minhash"]):
            index[k].append(j)
    removed = {}
    for r in train:
        if r["norm_hash"] in norm:
            removed[r["id"]] = "norm_hash"
        elif r["shape_hash"] in shape:
            removed[r["id"]] = "shape_hash"
        else:
            cand = {j for k in _bands(r["minhash"]) for j in index.get(k, ())}
            if any(jaccard(r["shingles"], test[j]["shingles"]) >= JACCARD_MIN for j in sorted(cand)):
                removed[r["id"]] = "jaccard"
    for r in train:
        if r["source"] == "mutation" and r["id"] not in removed and r.get("pair_id") in removed:
            removed[r["id"]] = "pair_removed"
    return [r for r in train if r["id"] not in removed], removed


def small_train(rows: list[dict], target: int = SMALL_TARGET, seed: int = SEED) -> tuple[list[dict], int]:
    """Every label-1, mutation-original and real fixed row, plus corpus negatives capped per group (the largest cap
    that fits `target`, a seeded few groups get one more to reach it). Returns (rows, cap)."""
    keep = {r["id"] for r in rows if r["label"] == 1 or r["source"] != "corpus"}
    by_group = collections.defaultdict(list)
    for r in rows:
        if r["id"] not in keep:
            by_group[r["group"]].append(r)
    budget = max(0, target - len(keep))
    sizes = sorted(len(v) for v in by_group.values())
    cap = max(sizes, default=0)
    if sum(sizes) > budget:
        cap = 0
        while sum(min(n, cap + 1) for n in sizes) <= budget:
            cap += 1
    extra = budget - sum(min(n, cap) for n in sizes)
    rng = random.Random(seed)
    over = sorted(g for g, v in by_group.items() if len(v) > cap)
    rng.shuffle(over)
    take = {g: min(len(v), cap) for g, v in by_group.items()}
    for g in over[:max(0, extra)]:
        take[g] += 1
    for g, v in by_group.items():
        v = sorted(v, key=lambda r: hashlib.sha1(f"{seed}|{r['id']}".encode()).hexdigest())
        keep |= {r["id"] for r in v[:take[g]]}
    return [r for r in rows if r["id"] in keep], cap


# ---------------------------------------------------------------- pipeline
def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _sig_worker(code: str) -> dict:
    return signatures(code)


def fork_roots() -> dict:
    """lower-case repo -> fork-network root: GitHub source from the resolver's cache, else the fork_of chain."""
    parent = {}
    for r in _load(RAW / "repos.jsonl"):
        if r.get("fork_of"):
            parent[r["repo"].lower()] = r["fork_of"].lower()
    roots = {}
    for k in parent:
        seen, cur = {k}, parent[k]
        while cur in parent and parent[cur] not in seen:
            seen.add(cur)
            cur = parent[cur]
        roots[k] = cur
    meta = RAW / "resolve_cache" / "repo_meta.json"
    for k, m in (json.loads(meta.read_text()) if meta.exists() else {}).items():
        if m.get("root") and m["root"].lower() != k:
            roots[k] = m["root"].lower()
    return roots


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _write(path: Path, rows: list[dict]) -> None:
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps({k: v for k, v in r.items() if k not in TEMP}, sort_keys=False) + "\n")


def _key(r: dict) -> tuple:
    return (r["source"], r["label"], r["vuln_class"] or "-")


def main() -> None:
    log = collections.Counter()
    real = _load(DATA / "real_samples.jsonl")
    mut = _load(DATA / "mutation_samples.jsonl")
    corpus = _load(DATA / "corpus_samples.jsonl")
    n_in = {"real": len(real), "mutation": len(mut), "corpus": len(corpus)}

    # mutation sources the corpus rules exclude (security demos / vulnerability datasets, generated, vendored, sdk)
    kept_mut = []
    for r in mut:
        reason = drop_reason(r["path"], r["group"], False)
        if reason:
            log[f"mutation_dropped_{reason}_{r['source']}"] += 1
        else:
            kept_mut.append(r)
    mut = kept_mut

    roots = fork_roots()
    for r in mut + corpus:
        g = canonical_group(r["group"], ALIASES, roots)
        if g != r["group"]:
            log[f"group_remapped_{r['source']}"] += 1
            r["group"] = g
    rows = real + mut + corpus
    with Pool(17) as pool:
        sigs = pool.map(_sig_worker, [r["code"] for r in rows], chunksize=256)
    for r, s in zip(rows, sigs):
        if r["source"] == "corpus" and r.get("norm_hash") and r["norm_hash"] != s["norm_hash"]:
            log["corpus_norm_hash_mismatch"] += 1
        r.update(s)

    rows, conflicts = resolve_conflicts(rows)
    log.update(conflicts)
    labels = collections.defaultdict(set)
    for r in rows:
        labels[r["norm_hash"]].add(r["label"])
    assert not [h for h, v in labels.items() if len(v) > 1], "label conflict left after resolve_conflicts"

    copies = copy_groups(rows)
    for r in rows:
        if r["group"] in copies:
            log[f"copy_group_{r['source']}"] += 1
            r["repo_group"] = r["group"]
            r["group"] = copies[r["group"]]
    test_groups, split_info = pick_test_groups(rows)
    split_info["copy_groups"] = dict(sorted(copies.items()))
    test = [r for r in rows if r["group"] in test_groups]
    train = [r for r in rows if r["group"] not in test_groups]
    test, log["dedupe_test"] = dedupe(test)
    train, log["dedupe_train"] = dedupe(train)
    n_train_pre = collections.Counter(_key(r)[:2] for r in train)
    train, leaks = remove_leaks(train, test)
    src_of = {r["id"]: r["source"] for r in rows}
    leak_counts = collections.Counter((reason, src_of[i]) for i, reason in leaks.items())

    ids_tr, ids_te = {r["id"] for r in train}, {r["id"] for r in test}
    assert len(ids_tr) == len(train) and len(ids_te) == len(test), "duplicate id within a split"
    assert not ids_tr & ids_te, "id shared between train and test"
    assert not {r["group"] for r in train} & {r["group"] for r in test}, "group shared between train and test"
    assert not {r["norm_hash"] for r in train} & {r["norm_hash"] for r in test}, "norm_hash shared"
    assert not {r["shape_hash"] for r in train} & shape_targets(test), "shape_hash of a test real row in train"

    small, cap = small_train(train)
    out = {"train_v1.jsonl": train, "test_v1.jsonl": test, "train_v1_small.jsonl": small}
    for name, rs in out.items():
        _write(DATA / name, rs)
    counts = collections.Counter()
    for split, rs in out.items():
        for r in rs:
            counts["|".join(map(str, (split.removesuffix(".jsonl"),) + _key(r)))] += 1
    manifest = {
        "seed": SEED, "rules": {"test_share": TEST_SHARE, "test_cap": TEST_CAP, "time_split_since": SINCE,
                                "jaccard_min": JACCARD_MIN, "shingle": SHINGLE, "small_target": SMALL_TARGET,
                                "small_corpus_cap_per_group": cap},
        "inputs": {p: _sha256(DATA / p) for p in ("real_samples.jsonl", "mutation_samples.jsonl",
                                                     "corpus_samples.jsonl")},
        "files": {name: {"sha256": _sha256(DATA / name), "rows": len(rs)} for name, rs in out.items()},
        "groups": {"test": sorted({r["group"] for r in test}), "train": sorted({r["group"] for r in train})},
        "split": split_info,
        "counts": dict(sorted(counts.items())),
        "ids": {"test": sorted(ids_te), "train": sorted(ids_tr), "train_small": sorted(r["id"] for r in small)},
    }
    (DATA / "split_manifest_v1.json").write_text(json.dumps(manifest, indent=1) + "\n")
    report = write_report(n_in, log, split_info, out, leak_counts, n_train_pre, cap, manifest)
    (DATA / "assembly_report.md").write_text(report)
    print(report)


def _pct(xs: list[int], q: float) -> int:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0


def write_report(n_in, log, info, out, leak_counts, n_train_pre, cap, manifest) -> str:
    train, test, small = out["train_v1.jsonl"], out["test_v1.jsonl"], out["train_v1_small.jsonl"]
    L = ["# Assembly report (train_v1 / sealed test_v1)", "",
         f"Seed {SEED}. Built by `uv run python -m near.collect.assemble` from real_samples ({n_in['real']}), "
         f"mutation_samples ({n_in['mutation']}) and corpus_samples ({n_in['corpus']}).", "",
         "## Output", "", "| file | rows | sha256 |", "|---|---|---|"]
    L += [f"| {n} | {v['rows']} | `{v['sha256']}` |" for n, v in manifest["files"].items()]
    L += ["", "## Rules applied, in order, and rows touched", "", "| rule | rows |", "|---|---|"]
    L += [f"| mutation rows dropped by the corpus file rules (`{k.removeprefix('mutation_dropped_')}`): security-demo "
          f"repos / vulnerability datasets, demo dirs, generated, vendored, sdk internals | {v} |"
          for k, v in sorted(log.items()) if k.startswith("mutation_dropped_")]
    L += [f"| corpus/mutation group mapped to the real rows' group (resolver alias or fork-network root), "
          f"{k.removeprefix('group_remapped_')} | {v} |" for k, v in sorted(log.items()) if k.startswith("group_remapped_")]
    L += [f"| row of a repo that copies a real-label project (>= {COPY_MIN_ROWS} rows of one real group near-copied at "
          f"Jaccard >= {COPY_JACCARD}, rows copied by > {COPY_MAX_GROUPS} repos ignored; two real groups join only if the "
          f"copied rows are >= {COPY_MIN_SHARE:.0%} of the smaller one's functions) moved into that group, "
          f"{k.removeprefix('copy_group_')}; own group kept in `repo_group` | {v} |"
          for k, v in sorted(log.items()) if k.startswith("copy_group_")]
    L += [f"| corpus norm_hash recomputed here differs from extract_corpus's | {log['corpus_norm_hash_mismatch']} |",
          f"| corpus / mutation_original row identical (norm_hash) to a real label-1 row -> label 1, that vuln_class, "
          f"`relabeled_from_real=true` (corpus {log['relabeled_from_real_corpus']}, mutation_original "
          f"{log['relabeled_from_real_mutation_original']}) | {log['relabeled_from_real']} |",
          f"| real fixed (label 0) row identical to a real label-1 row: dropped | "
          f"{log['dropped_real_fixed_same_as_vulnerable']} |",
          f"| mutant identical to label-0 code: dropped | {log['dropped_mutant_same_as_label0']} |",
          f"| exact (norm_hash, label) duplicates within test dropped (kept order incident, audit, fix_commit, mutation, "
          f"mutation_original, corpus) | {log['dedupe_test']} |",
          f"| same, within train | {log['dedupe_train']} |"]
    for (reason, src), v in sorted(leak_counts.items()):
        L.append(f"| train row removed as a copy of a test row: `{reason}`, {src} | {v} |")
    L += ["", "Leak rules: `norm_hash` = same code after removing comments and collapsing whitespace; `shape_hash` = "
          "same token sequence after renaming identifiers consistently ($0, $1, ...) and replacing literals, checked "
          f"only against test real rows of >= {SHAPE_MIN_TOKENS} tokens (shorter functions such as guarded setters "
          "share shapes without being copies); "
          f"`jaccard` = token 5-gram Jaccard >= {JACCARD_MIN} with any test row (string literals replaced; MinHash LSH "
          f"{N_PERM} perms / {BANDS} bands for candidates, verified exactly); `pair_removed` = mutant whose original "
          "was removed. norm_hash and Jaccard compare every test row (real, mutation, mutation_original, corpus) with "
          "every train row.",
          "", "Checks (asserted): no shared id, group or norm_hash between train and test; no train row with the "
          "shape_hash of a long test real row; no norm_hash with two labels.", ""]

    L += ["## Sealed test groups", "",
          f"- Real-label groups (audit / incident / fix_commit label 1): {info['real_label_groups']}",
          f"- Time split, every group with an audit/incident row dated >= {SINCE}: {len(info['time_split_groups'])}",
          f"- Seeded random share of the remaining groups, stratified by (dominant vuln_class, dominant source): "
          f"{info['random_groups']} (target {TEST_SHARE:.0%} of the remaining groups = {round(TEST_SHARE * (info['real_label_groups'] - len(info['time_split_groups'])))}, "
          f"reduced until the test holds at most {TEST_CAP:.0%} of the real-label groups and at most {TEST_CAP:.0%} of "
          "the real label-1 rows)",
          f"- Test real-label groups: {len(info['time_split_groups']) + info['random_groups']} of "
          f"{info['real_label_groups']}; test groups in all: {len(manifest['groups']['test'])}, train groups: "
          f"{len(manifest['groups']['train'])}", "",
          "Time-split groups: " + ", ".join(f"`{g}`" for g in info["time_split_groups"]), "",
          "Random groups: " + ", ".join(f"`{g}`" for g in info["random_group_list"]), "",
          f"Copy repos merged into a real-label group ({len(info['copy_groups'])}; split of the real group): "
          + ", ".join(f"`{a}` -> `{b}` ({'test' if b in set(manifest['groups']['test']) else 'train'})"
                      for a, b in sorted(info["copy_groups"].items())), ""]

    L += ["## Counts: split x source x label", "", "| source | label | train | test | train_small | "
          "train before leak removal |", "|---|---|---|---|---|---|"]
    c = {n: collections.Counter(_key(r)[:2] for r in rs) for n, rs in out.items()}
    for k in sorted(set().union(*c.values(), n_train_pre), key=lambda k: (SOURCE_RANK[k[0]], k[1])):
        L.append(f"| {k[0]} | {k[1]} | {c['train_v1.jsonl'][k]} | {c['test_v1.jsonl'][k]} | "
                 f"{c['train_v1_small.jsonl'][k]} | {n_train_pre[k]} |")
    L += [f"| **all** | | {len(train)} | {len(test)} | {len(small)} | {sum(n_train_pre.values())} |", ""]

    L += ["## Label-1 rows by vuln_class", "", "| vuln_class | train real | test real | train mutation | "
          "test mutation | train relabeled corpus/mut-orig | test relabeled |", "|---|---|---|---|---|---|---|"]
    def cls(rs, kind):
        out_ = collections.Counter()
        for r in rs:
            if r["label"] != 1:
                continue
            k = ("real" if r["source"] in REAL else "mutation" if r["source"] == "mutation" else "relabeled")
            if k == kind:
                out_[r["vuln_class"] or "-"] += 1
        return out_
    t = {(s, k): cls(rs, k) for s, rs in (("tr", train), ("te", test)) for k in ("real", "mutation", "relabeled")}
    for v in sorted(set().union(*t.values())):
        L.append(f"| {v} | {t['tr', 'real'][v]} | {t['te', 'real'][v]} | {t['tr', 'mutation'][v]} | "
                 f"{t['te', 'mutation'][v]} | {t['tr', 'relabeled'][v]} | {t['te', 'relabeled'][v]} |")
    L.append("")

    L += ["## Real rows in each split", "", "| split | source | label | rows | code_from_snippet | dated >= 2025 | "
          "groups |", "|---|---|---|---|---|---|---|"]
    for name, rs in (("train", train), ("test", test)):
        for s in REAL:
            for lab in (1, 0):
                sel = [r for r in rs if r["source"] == s and r["label"] == lab]
                L.append(f"| {name} | {s} | {lab} | {len(sel)} | {sum(bool(r.get('code_from_snippet')) for r in sel)} "
                         f"| {sum((r.get('date') or '') >= SINCE for r in sel)} | {len({r['group'] for r in sel})} |")
    ids = {r["id"] for r in train} | {r["id"] for r in test}
    dangling = sum(1 for r in train + test if r.get("pair_id") and r["pair_id"] not in ids)
    L += ["", f"Rows whose pair_id points to a row no longer present (dropped by a rule above): {dangling}.", ""]

    L += ["## Function length (n_lines) by split, source and label", "",
          "Check for a length shortcut: extract_corpus drops trivial functions (< 2 statements or body < 3 lines) "
          "from the corpus only.", "", "| split | source | label | rows | p10 | median | p90 | share <= 5 lines |",
          "|---|---|---|---|---|---|---|---|"]
    for name, rs in (("train", train), ("test", test)):
        g = collections.defaultdict(list)
        for r in rs:
            g[_key(r)[:2]].append(len(r["code"].splitlines()))
        for k in sorted(g, key=lambda k: (SOURCE_RANK[k[0]], k[1])):
            xs = g[k]
            L.append(f"| {name} | {k[0]} | {k[1]} | {len(xs)} | {_pct(xs, .1)} | {statistics.median(xs):g} | "
                     f"{_pct(xs, .9)} | {sum(x <= 5 for x in xs) / len(xs):.1%} |")
    L += ["", "## train_v1_small", "",
          f"All label-1 rows, all mutation_original rows and all real fixed rows of train, plus corpus negatives capped "
          f"at {cap} per group (seeded per-row hash order; a seeded set of groups gets one more row to reach the target "
          f"{SMALL_TARGET}): {len(small)} rows.", "",
          "## Limits", "",
          "- Label 0 means not known vulnerable: corpus code is presumed safe, real label-0 rows are the function at "
          "the fix commit, mutation_original rows are unaudited code.",
          "- code_from_snippet rows (code from PDF text) have unverified commits and different whitespace; they are kept "
          "and flagged by that field.",
          "- Leak removal compares code text only. Different code of the same project in an unrelated repo (a copy that "
          "was edited more than the Jaccard threshold) can still sit across the split.",
          "- Corpus dates are repo last-commit dates and play no part in the time split.",
          "- Mutation recall must be reported separately from real recall; mutants are synthetic.", ""]
    return "\n".join(L)


if __name__ == "__main__":
    main()
