"""Corpus negatives: every non-trivial, non-test function of every near_sdk .rs file at HEAD of each cloned repo.

    uv run python -m near.collect.extract_corpus [--workers 17]
    -> near/data/corpus_samples.jsonl (sample schema, label 0, source corpus) + near/data/corpus_report.md

Filters, in order: test fns; security demos/fixtures and generated/vendored/near-sdk-internal paths; trivial fns
(< 2 statements, counting statements of nested blocks, or a body under 3 lines); code identical to a function named
by an audit finding, a fix commit (at its parent) or an incident; exact duplicates of the comment-free,
whitespace-collapsed code across the whole corpus (kept in the repo with most stars, then earliest last_commit;
`dup_count` on the kept row). Cloned repos are untrusted data: files are only read and parsed.
"""
import argparse
import collections
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool
from pathlib import Path

from near.analyzer import extract_functions
from near.analyzer.rust_parse import PARSER
from near.collect.corpus import GIT_ENV, RAW, REPOS_JSONL, repo_from_url, uses_near_sdk

OUT = Path("near/data/corpus_samples.jsonl")
REPORT = Path("near/data/corpus_report.md")
CANONICAL_SDK = "near/near-sdk-rs"
SDK_DIR = re.compile(r"near-(sdk|sys|contract-standards)[-\w.]*")  # near-sdk-rs crates, also versioned copies
# cargo-expand output, `@generated` headers, transpiler output opening with a long `#![allow(..)]` list
GENERATED_HEAD = re.compile(r"\A(?:.*\n){0,4}.*@generated|\A(?:.*\n){0,2}#!\[allow\(([^,\n]*,){4,}")
# Vulnerability datasets, CTFs, deliberately vulnerable demos and scanner fixture repos: not presumed-safe code.
SECURITY_DEMO_REPOS = {
    "shenyimings/forge-s-artifacts", "blocksecteam/rustle", "enterprise46722/rustle", "ldawson-457gj/rustlee",
    "blocksecteam/near_demo", "ahnafalfariza/scavene-vulnerable-contract", "halbornsecurity/ctfs",
    "hashcloak/near-vulnerabilities", "zigtur/vulnerable-near-contract", "resonancecybersecurity/ctf",
    "advancedblockchainsecurity/rustdefend", "eliqaq/intellibridge-auditor", "vinibarbosabr/nearsc-auditor",
    "oathwallet/oath-wallet-security-review", "wonkared/preflight", "chokri29/sentinelreview"}
DEMO_DIR = re.compile(r"(test[-_]?)?fixtures?|testdata|test[-_]data|.*vulnerab.*|exploit[-_].*|evil[-_].*|buggy|"
                      r".*_unsafe|attack(er|[-_]contract)?", re.I)
COMMENTS = {"line_comment", "block_comment"}
FN_KEYS = ["fn", "impl", "trait", "is_near_bindgen", "attrs", "is_public", "is_payable"]


def _comment_ranges(node, out: list) -> list:
    for c in node.children:
        if c.type in COMMENTS:
            out.append((c.start_byte, c.end_byte))
        else:
            _comment_ranges(c, out)
    return out


def norm_code(code: str) -> str:
    """Function code with comments (doc comments included) removed and whitespace collapsed."""
    b = code.encode("utf8", errors="replace")
    parts, pos = [], 0
    for s, e in _comment_ranges(PARSER.parse(b).root_node, []):
        parts.append(b[pos:s])
        pos = e
    parts.append(b[pos:])
    return re.sub(r"\s+", " ", b" ".join(parts).decode("utf8", errors="replace")).strip()


def norm_hash(code: str) -> str:
    return hashlib.sha1(norm_code(code).encode()).hexdigest()


def body_stats(code: str) -> tuple[int, int]:
    """(statements in the body, counting those of nested blocks; lines the body spans)."""
    root = PARSER.parse(code.encode("utf8", errors="replace")).root_node
    fn = next((c for c in root.children if c.type == "function_item"), None)
    body = fn.child_by_field_name("body") if fn is not None else None
    if body is None:
        return 0, 0
    n, stack = 0, [body]
    while stack:
        node = stack.pop()
        if node.type == "block":
            n += sum(1 for c in node.named_children if c.type not in COMMENTS)
        stack.extend(node.named_children)
    return n, body.end_point[0] - body.start_point[0] + 1


def is_trivial(code: str) -> bool:
    stmts, lines = body_stats(code)
    return stmts < 2 or lines < 3


def is_sdk_copy(paths: list[str], repo: str) -> bool:
    """A fork or copy of near-sdk-rs: near-sdk/src at the repo root, other than the canonical repo."""
    return repo.lower() != CANONICAL_SDK and any(p.startswith("near-sdk/src/") for p in paths)


def drop_reason(path: str, repo: str, sdk_copy: bool, head: str = "") -> str | None:
    """Why a file is not corpus code (security demo/fixture, generated, vendored, near-sdk internals), else None.
    `head` is the start of the file."""
    segs = path.split("/")[:-1]
    if repo.lower() in SECURITY_DEMO_REPOS or any(DEMO_DIR.fullmatch(s) for s in segs):
        return "security_demo"
    if "target" in segs or re.search(r"_expand(ed)?\.rs$", path) or GENERATED_HEAD.search(head):
        return "generated"
    if {"vendor", "vendors", "node_modules", ".cargo"} & set(segs):
        return "vendored"
    sdk = {s for s in segs if SDK_DIR.fullmatch(s)}
    if sdk and not (repo.lower() == CANONICAL_SDK and sdk == {"near-contract-standards"}):
        return "near_sdk_internal"
    if sdk_copy and segs[:1] == ["examples"]:
        return "near_sdk_internal"
    return None


def rs_files(root: Path) -> list[str]:
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x != ".git"]
        for f in files:
            p = Path(d) / f
            if f.endswith(".rs") and not p.is_symlink():
                out.append(p.relative_to(root).as_posix())
    return sorted(out)


def repo_samples(meta: dict) -> tuple[list[dict], dict]:
    """Sample rows and filter counts for one cloned repo."""
    root, repo = Path(meta["local_path"]), meta["repo"]
    st = collections.Counter(repos=1)
    if not root.is_dir():
        return [], collections.Counter(missing_clone=1)
    paths = rs_files(root)
    sdk_copy = is_sdk_copy(paths, repo)
    st["sdk_copy"] = int(sdk_copy)
    group, rows = repo.lower(), []
    for path in paths:
        try:
            p = root / path
            if p.stat().st_size > 5_000_000:
                continue
            src = p.read_text(errors="replace")
        except OSError:
            continue
        if not uses_near_sdk(src):
            continue
        st["contract_files"] += 1
        reason = drop_reason(path, repo, sdk_copy, src[:2000])
        if reason:
            st[f"files_{reason}"] += 1
        for f in extract_functions(src, path):
            st["fns"] += 1
            if f["is_test"]:
                st["test"] += 1
            elif reason:
                st[reason] += 1
            elif is_trivial(f["code"]):
                st["trivial"] += 1
            else:
                rows.append(sample_row(f, meta, group))
    st["kept_pre_dedupe"] = len(rows)
    return rows, st


def sample_row(f: dict, meta: dict, group: str) -> dict:
    code, path, head = f["code"], f["path"], meta["head_commit"]
    return {
        "id": hashlib.sha1(f"{group}|{path}|{f['fn']}|{code}".encode()).hexdigest(), "code": code,
        **{k: f[k] for k in FN_KEYS},
        "label": 0, "vuln_class": None, "severity": None, "source": "corpus", "group": group,
        "repo": f"https://github.com/{meta['repo']}", "commit": head, "path": path,
        "start_line": f["start_line"], "end_line": f["end_line"], "date": meta.get("last_commit"),
        "evidence": f"https://github.com/{meta['repo']}/blob/{head}/{path}#L{f['start_line']}-L{f['end_line']}",
        "pair_id": None, "stars": meta.get("stars") or 0, "audited": bool(meta.get("audited")),
        "near_sdk_version": meta.get("near_sdk_version"), "norm_hash": norm_hash(code), "n_lines": len(code.splitlines()),
    }


def dedupe(rows: list[dict]) -> list[dict]:
    """One row per norm_hash: most stars, then earliest date; dup_count / dup_repos record the copies."""
    by_hash = collections.defaultdict(list)
    for r in rows:
        by_hash[r["norm_hash"]].append(r)
    out = []
    for copies in by_hash.values():
        best = min(copies, key=lambda r: (-(r["stars"] or 0), r["date"] or "9999", r["group"], r["path"], r["start_line"]))
        out.append({**best, "dup_count": len(copies), "dup_repos": len({r["group"] for r in copies})})
    return out


def vulnerable_refs(audits: list[dict], fixes: list[dict], incidents: list[dict]) -> set[tuple]:
    """(owner/repo lower-case, commit, path, fn) of functions known vulnerable at that commit."""
    out = set()
    for a in audits:
        repo = repo_from_url(a.get("repo"))
        if repo and a.get("commit") and a.get("path") and a.get("fn"):
            out.add((repo.lower(), a["commit"], re.sub(r"\s+", "", a["path"]), a["fn"].split("::")[-1]))
    for x in fixes:
        out |= {(x["repo"].lower(), x["parent"], p, fn) for p in x.get("files") or [] for fn in x.get("fns") or []}
    for i in incidents:
        repo = repo_from_url(i.get("repo"))
        commit = i.get("vuln_commit") or (i.get("fix_commit") and f"{i['fix_commit']}^")
        if repo and commit and i.get("path") and i.get("fn"):
            out.add((repo.lower(), commit, i["path"], i["fn"].split("::")[-1]))
    return out


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in open(path)] if path.exists() else []


def known_vulnerable_hashes(local: dict[str, str]) -> tuple[set[str], collections.Counter]:
    """norm_hash of every function named by audit findings, fix commits (at the parent) and incidents, read from
    the local clones with `git show` (blobs fetched lazily)."""
    audits = [r for p in sorted(RAW.glob("audit_findings/*.jsonl")) if "manifest" not in p.name for r in _load(p)]
    refs = vulnerable_refs(audits, _load(RAW / "fix_commits.jsonl"), _load(RAW / "incidents.jsonl"))
    files = collections.defaultdict(set)
    for repo, commit, path, fn in refs:
        files[(repo, commit, path)].add(fn)
    st = collections.Counter(refs=len(refs), ref_files=len(files))

    def show(key):
        repo, commit, path = key
        if repo not in local:
            return key, None
        try:
            r = subprocess.run(["git", "-C", local[repo], "show", f"{commit}:{path}"], capture_output=True,
                               env=GIT_ENV, timeout=120)
        except subprocess.TimeoutExpired:
            return key, None
        return key, r.stdout.decode("utf8", errors="replace") if r.returncode == 0 else None

    hashes = set()
    with ThreadPoolExecutor(16) as ex:
        for key, src in ex.map(show, files):
            if src is None:
                st["ref_files_unreadable"] += 1
                continue
            for f in extract_functions(src, key[2]):
                if f["fn"] in files[key]:
                    hashes.add(norm_hash(f["code"]))
    st["hashes"] = len(hashes)
    return hashes, st


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f}%" if b else "n/a"


def write_report(stats: dict[str, collections.Counter], n_pre: int, kept: list[dict], vuln: collections.Counter) -> str:
    tot = sum(stats.values(), collections.Counter())
    per_repo = collections.Counter(r["group"] for r in kept)
    counts = sorted(per_repo.get(g, 0) for g in stats if stats[g]["repos"])
    stars = {r["group"]: r["stars"] for r in kept}
    cross = sum(1 for r in kept if r["dup_repos"] > 1)
    removed = n_pre - len(kept)
    q = statistics.quantiles(counts, n=20) if len(counts) > 1 else [0] * 19
    buckets = collections.Counter(next(lab for lim, lab in [(0, "0"), (10, "1-10"), (50, "11-50"), (200, "51-200"),
                                                            (1000, "201-1000"), (10**9, ">1000")] if c <= lim)
                                  for c in counts)
    top = per_repo.most_common(25)
    n = len(kept)
    lines = [
        "# NEAR corpus extraction report", "",
        "Corpus negatives (`label 0`, `source corpus`) from HEAD of each clone in `near/data/raw/repos.jsonl`, "
        "produced by `near/collect/extract_corpus.py` with `near.analyzer.extract_functions`.", "",
        "## Funnel", "",
        "| Stage | Count |", "|---|---|",
        f"| repos in repos.jsonl | {tot['repos'] + tot['missing_clone']} |",
        f"| repos without a local clone | {tot['missing_clone']} |",
        f"| near-sdk-rs forks/copies detected (near-sdk/src at root; their sdk dirs and examples/ dropped) | {tot['sdk_copy']} |",
        f"| contract .rs files (use near_sdk) | {tot['contract_files']} |",
        f"| of which security demos / fixtures (vuln datasets, CTFs, scanner fixtures, exploit/attacker dirs) | {tot['files_security_demo']} |",
        f"| of which generated (/target/, cargo-expand output, @generated or transpiler headers) | {tot['files_generated']} |",
        f"| of which vendored (/vendor/, /vendors/, node_modules, .cargo) | {tot['files_vendored']} |",
        f"| of which near-sdk internals (sdk crate dirs outside the canonical repo's near-contract-standards) | {tot['files_near_sdk_internal']} |",
        f"| functions extracted (with a body) | {tot['fns']} |",
        f"| - test functions dropped | {tot['test']} |",
        f"| - functions in security demos / fixtures dropped | {tot['security_demo']} |",
        f"| - functions in generated files dropped | {tot['generated']} |",
        f"| - functions in vendored files dropped | {tot['vendored']} |",
        f"| - functions in near-sdk internals dropped | {tot['near_sdk_internal']} |",
        f"| - trivial functions dropped (< 2 statements incl. nested blocks, or body < 3 lines) | {tot['trivial']} |",
        f"| - code identical (norm_hash) to a known-vulnerable function (audit / fix-commit parent / incident) | {vuln['dropped']} |",
        f"| = before dedupe | {n_pre} |",
        f"| - exact norm_hash duplicates dropped | {removed} |",
        f"| = **kept rows** | **{n}** |", "",
        f"Known-vulnerable functions: {vuln['refs']} (repo, commit, path, fn) refs in {vuln['ref_files']} files, "
        f"{vuln['ref_files_unreadable']} files unreadable (no clone / missing blob), {vuln['hashes']} distinct norm_hashes; "
        f"{vuln['dropped']} corpus rows matched in {vuln['dropped_repos']} repos.", "",
        f"Kept rows that had copies: {sum(1 for r in kept if r['dup_count'] > 1)} "
        f"({cross} with copies in other repos). Largest dup_count: "
        + ", ".join(f"`{r['fn']}` x{r['dup_count']} ({r['dup_repos']} repos)"
                    for r in sorted(kept, key=lambda r: -r["dup_count"])[:8]) + ".", "",
        "## Shares (kept rows)", "",
        f"- inside a `#[near_bindgen]` / `#[near]` impl: {sum(r['is_near_bindgen'] for r in kept)} ({pct(sum(r['is_near_bindgen'] for r in kept), n)})",
        f"- public (`pub` or trait-impl method): {sum(r['is_public'] for r in kept)} ({pct(sum(r['is_public'] for r in kept), n)})",
        f"- public and in a bindgen impl (contract entry points): "
        f"{sum(r['is_public'] and r['is_near_bindgen'] for r in kept)} ({pct(sum(r['is_public'] and r['is_near_bindgen'] for r in kept), n)})",
        f"- `#[payable]`: {sum(r['is_payable'] for r in kept)}; `#[private]`: {sum('private' in r['attrs'] for r in kept)}",
        f"- from repos marked audited: {sum(r['audited'] for r in kept)} ({pct(sum(r['audited'] for r in kept), n)})",
        f"- n_lines median {statistics.median([r['n_lines'] for r in kept]) if kept else 0}, "
        f"max {max((r['n_lines'] for r in kept), default=0)}", "",
        "## Functions per repo (kept rows, repos with a clone)", "",
        f"- repos contributing rows: {len(per_repo)} of {len(counts)}",
        f"- median {statistics.median(counts) if counts else 0}, mean {statistics.mean(counts) if counts else 0:.1f}, "
        f"p90 {q[17]:.0f}, p95 {q[18]:.0f}, max {max(counts, default=0)}",
        f"- top 10 repos hold {pct(sum(c for _, c in per_repo.most_common(10)), n)} of rows, "
        f"top 50 hold {pct(sum(c for _, c in per_repo.most_common(50)), n)}", "",
        "| fns in repo | repos |", "|---|---|",
        *[f"| {lab} | {buckets.get(lab, 0)} |" for lab in ["0", "1-10", "11-50", "51-200", "201-1000", ">1000"]], "",
        "## Top repos", "", "| repo | stars | kept fns | extracted fns | trivial | test |", "|---|---|---|---|---|---|",
        *[f"| {g} | {stars.get(g, 0)} | {c} | {stats[g]['fns']} | {stats[g]['trivial']} | {stats[g]['test']} |" for g, c in top], "",
        "## near-sdk-rs copies detected", "",
        ", ".join(sorted(g for g, s in stats.items() if s["sdk_copy"])) or "none", "",
        "## Security demo repos dropped whole", "",
        "Vulnerability datasets, CTFs, deliberately vulnerable demos and scanner fixture repos (their code is not "
        "presumed safe): " + ", ".join(sorted(SECURITY_DEMO_REPOS)) + ". Directories named fixtures/testdata, "
        "`*vulnerab*`, `exploit-*`, `evil-*`, `buggy`, `*_unsafe`, `attack`/`attacker` are dropped in every repo.", "",
        "## Notes", "",
        "- Only files that reference `near_sdk` are read (same rule as `corpus.index`); helper modules of a contract "
        "crate that never name `near_sdk` (e.g. `use crate::*` only) are not in the corpus.",
        "- Trivial functions are counted but not emitted; one-statement setters/getters are therefore absent from "
        "the negatives (relevant if positives include short unguarded setters).",
        "- Only exact (norm_hash) duplicates are removed; near-duplicates (older snapshots and lightly edited copies "
        "of the same project, e.g. stale forks of audited repos) remain and need the split-time near-dup check.",
        "- `date` is the repo's last commit, not the function's; `label 0` means not known vulnerable, not verified safe.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workers", type=int, default=17)
    a = ap.parse_args()
    metas = [json.loads(line) for line in open(REPOS_JSONL)]
    rows, stats = [], {}
    with Pool(a.workers) as pool:
        for i, (meta, (rs, st)) in enumerate(zip(metas, pool.imap(repo_samples, metas, chunksize=2)), 1):
            rows += rs
            stats[meta["repo"].lower()] = st
            if i % 200 == 0:
                print(f"{i}/{len(metas)} repos, {len(rows)} rows", file=sys.stderr, flush=True)
    vuln_hashes, vuln = known_vulnerable_hashes({m["repo"].lower(): m["local_path"] for m in metas})
    clean = [r for r in rows if r["norm_hash"] not in vuln_hashes]
    vuln["dropped"] = len(rows) - len(clean)
    vuln["dropped_repos"] = len({r["group"] for r in rows if r["norm_hash"] in vuln_hashes})
    rows = clean
    kept = sorted(dedupe(rows), key=lambda r: (r["group"], r["path"], r["start_line"]))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w") as f:
        for r in kept:
            f.write(json.dumps(r) + "\n")
    REPORT.write_text(write_report(stats, len(rows), kept, vuln))
    print(f"wrote {len(kept)} rows to {OUT} ({len(rows)} before dedupe); report {REPORT}", file=sys.stderr)


if __name__ == "__main__":
    main()
