"""Corpus of NEAR Rust smart-contract repos: discover on GitHub, clone, index into repos.jsonl.

    uv run python -m near.collect.corpus discover   # -> near/data/raw/repos/.candidates.jsonl
    uv run python -m near.collect.corpus clone      # -> near/data/raw/repos/<owner>__<repo>
    uv run python -m near.collect.corpus index      # -> near/data/raw/repos.jsonl

Cloned repos are untrusted data: they are only read as text, never built or executed.
"""
import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

RAW = Path("near/data/raw")
REPOS_DIR = RAW / "repos"
CANDIDATES = REPOS_DIR / ".candidates.jsonl"
SOURCES = REPOS_DIR / ".sources.json"
DROPPED = REPOS_DIR / ".dropped.jsonl"
REPOS_JSONL = RAW / "repos.jsonl"
MAX_KB = 300 * 1024
SKIP_DIRS = {".git", "target", "node_modules", "dist", "build", ".next", "vendor"}
UA = {"User-Agent": "near-security-oracle-research (dataset builder)"}

ORGS = ["near", "near-examples", "Near-One", "aurora-is-near", "ref-finance", "NearDeFi", "Meta-Pool",
        "linear-protocol", "defuse-protocol", "sweatco", "Mintbase", "ParasHQ", "PotLock", "NEARBuilders",
        "near-daos", "INTEARnear", "hot-dao", "Proximity-Labs", "octopus-network", "NearSocial", "calimero-network",
        "orderly-network", "tonic-foundation", "spin-fi", "pembrock-finance", "veax-finance", "sputnikdao", "near-ndc",
        "nearuaguild", "burrowfdn", "jumpdefi", "skyward-finance", "NEARFoundation", "near-apps", "evgenykuzyakov",
        "Learn-NEAR", "Learn-NEAR-Club", "bitte-ai", "fluxprotocol", "LiNEAR-protocol", "keypom", "nearai",
        "near-cli-rs", "HereWallet", "roke-to", "Paras-Digital", "HAPIprotocol", "Narwallets", "Cheddar-Farm",
        "NEAR-Edu", "kaiching", "tenk-dao", "zavodil", "NEARWEEK", "rhea-lab", "Shitzu-Apes", "nearcatalog"]
REPO_TOPICS = ["near", "near-protocol", "near-sdk", "nearprotocol", "near-blockchain", "near-smart-contract",
               "near-smart-contracts", "near-contract", "near-rust", "near-sdk-rs"]
REPO_QUERIES = ["near-sdk", "near_bindgen", "near smart contract rust", "near contract", "near protocol",
                "near-sdk-rs", "near dapp", "near nft", "near defi", "near dao", "near hackathon"]
CODE_QUERIES = ["near_sdk language:rust", "near_bindgen language:rust", "\"near-sdk\" filename:Cargo.toml",
                "\"use near_sdk\" path:src/lib.rs", "\"#[near(contract_state)]\" language:rust",
                "\"near_sdk::collections\" language:rust", "\"near_sdk::store\" language:rust",
                "\"#[private]\" near_sdk language:rust", "\"env::predecessor_account_id\" language:rust",
                "\"ext_contract\" language:rust", "\"PanicOnDefault\" language:rust",
                "\"assert_one_yocto\" language:rust", "\"near_contract_standards\" language:rust",
                "\"near-sdk\" filename:Cargo.lock"] + [
                f"{q} language:rust size:{sz}" for q in ("near_sdk", "near_bindgen", "\"#[near(\"", "\"#[payable]\"")
                for sz in ("<1500", "1500..4000", "4000..10000", ">10000")]

GH_RE = re.compile(r"github\.com[:/]+([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
REPO_NAME_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
NEAR_SDK_RE = re.compile(r"(?<![A-Za-z0-9_])near_sdk(?![A-Za-z0-9_])")
AUDIT_RE = re.compile(r"(^|/)audits?(/|$)|audit[^/]*\.(pdf|md)$", re.I)


def repo_from_url(url: str | None) -> str | None:
    """`owner/repo` from a GitHub URL (https, ssh, with .git or a subpath), else None."""
    m = GH_RE.search(url or "")
    if not m:
        return None
    name = m.group(2)
    name = name[:-4] if name.endswith(".git") else name
    return f"{m.group(1)}/{name}" if name else None


def uses_near_sdk(src: str) -> bool:
    """True when Rust source references the `near_sdk` crate."""
    return bool(NEAR_SDK_RE.search(src))


def near_sdk_version(cargo_tomls: list[str], cargo_locks: list[str]) -> str | None:
    """Most common near-sdk version: resolved from Cargo.lock, else the requirement in Cargo.toml ("git" for git deps)."""
    locked = re.findall(r'name = "near-sdk"\nversion = "([^"]+)"', "\n".join(cargo_locks))
    if locked:
        return collections.Counter(locked).most_common(1)[0][0]
    found = []
    for toml in cargo_tomls:
        for m in re.finditer(r'^\s*near-sdk\s*=\s*(.+)$', toml, re.M):
            spec = m.group(1)
            v = re.match(r'"([^"]+)"', spec) or re.search(r'version\s*=\s*"([^"]+)"', spec)
            if v:
                found.append(v.group(1))
            elif "git" in spec:
                found.append("git")
        for m in re.finditer(r'^\[(?:[\w.-]+\.)?dependencies\.near-sdk\]\s*\n(?:[^\[]*?)version\s*=\s*"([^"]+)"', toml, re.M):
            found.append(m.group(1))
    return collections.Counter(found).most_common(1)[0][0] if found else None


def dedupe_forks(cands: dict[str, dict]) -> list[str]:
    """Drop forks whose parent is a candidate; of forks sharing an absent parent keep the most-starred one."""
    keep, orphans = [], collections.defaultdict(list)
    lower = {k.lower() for k in cands}
    for name, meta in cands.items():
        parent = meta.get("fork_of")
        if not parent:
            keep.append(name)
        elif parent.lower() not in lower:
            orphans[parent.lower()].append(name)
    for names in orphans.values():
        keep.append(max(names, key=lambda n: (cands[n].get("stars") or 0, n)))
    return keep


def is_audited(paths: list[str]) -> bool:
    """True when the repo has an audits/ folder or an audit report file."""
    return any(AUDIT_RE.search(p) for p in paths)


def local_dir(repo: str) -> Path:
    return REPOS_DIR / repo.replace("/", "__")


# ---------- discovery (network) ----------

def gh_json(args: list[str]):
    r = subprocess.run(["gh", *args], capture_output=True, text=True)
    try:
        return json.loads(r.stdout) if r.stdout.strip() else None
    except json.JSONDecodeError:
        return None


def crates_repos() -> set[str]:
    """Repository URLs of crates that depend on near-sdk (crates.io reverse dependencies)."""
    names, page = set(), 1
    with httpx.Client(headers=UA, timeout=30) as c:
        while True:
            d = c.get("https://crates.io/api/v1/crates/near-sdk/reverse_dependencies",
                      params={"per_page": 100, "page": page}).json()
            names |= {v["crate"] for v in d.get("versions", [])}
            if page * 100 >= d["meta"]["total"] or not d.get("versions"):
                break
            page += 1
            time.sleep(1)
        out = set()
        for n in sorted(names):
            time.sleep(1)
            repo = repo_from_url(c.get(f"https://crates.io/api/v1/crates/{n}").json().get("crate", {}).get("repository"))
            if repo:
                out.add(repo)
    print(f"crates.io: {len(names)} crates -> {len(out)} repos", file=sys.stderr)
    return out


def search(kind: str, q: str, pause: float, pages: int = 10) -> set[str]:
    out = set()
    for page in range(1, pages + 1):
        d = None
        for _ in range(3):
            d = gh_json(["api", "-X", "GET", f"search/{kind}", "-f", f"q={q}", "-f", "per_page=100", "-f", f"page={page}"])
            if d and "items" in d:
                break
            time.sleep(60)  # secondary rate limit
        time.sleep(pause)
        items = (d or {}).get("items") or []
        for it in items:
            out.add((it.get("repository") or it)["full_name"])
        if len(items) < 100:
            break
    print(f"search {kind} {q!r}: {len(out)}", file=sys.stderr)
    return out


def org_repos(org: str) -> set[str]:
    r = subprocess.run(["gh", "api", "--paginate", f"users/{org}/repos?per_page=100", "--jq", ".[].full_name"],
                       capture_output=True, text=True)
    return set(r.stdout.split()) if r.returncode == 0 else set()


META_Q = """nameWithOwner stargazerCount isArchived isFork isPrivate diskUsage parent { nameWithOwner }
licenseInfo { spdxId } languages(first: 15) { nodes { name } }
defaultBranchRef { target { ... on Commit { committedDate oid } } }"""


def fetch_meta(repos: list[str]) -> dict[str, dict]:
    """GitHub metadata per repo via batched GraphQL; missing/renamed-away repos are absent."""
    out = {}
    for i in range(0, len(repos), 40):
        chunk = repos[i:i + 40]
        parts = []
        for j, r in enumerate(chunk):
            o, n = r.split("/", 1)
            parts.append(f'r{j}: repository(owner: {json.dumps(o)}, name: {json.dumps(n)}) {{ {META_Q} }}')
        d = gh_json(["api", "graphql", "-f", "query={ " + "\n".join(parts) + " }"]) or {}
        for v in (d.get("data") or {}).values():
            if not v or v["isPrivate"]:
                continue
            tgt = (v.get("defaultBranchRef") or {}).get("target") or {}
            out[v["nameWithOwner"]] = {
                "repo": v["nameWithOwner"], "stars": v["stargazerCount"], "archived": v["isArchived"],
                "fork_of": (v.get("parent") or {}).get("nameWithOwner") if v["isFork"] else None,
                "size_kb": v["diskUsage"] or 0, "license": (v.get("licenseInfo") or {}).get("spdxId"),
                "languages": [x["name"] for x in v["languages"]["nodes"]],
                "last_commit": (tgt.get("committedDate") or "")[:10] or None,
            }
        time.sleep(0.5)
    return out


def gather_sources() -> dict[str, set]:
    """Candidate repo -> discovery sources, from crates.io, known orgs, repo search and code search."""
    sources = collections.defaultdict(set)
    for r in crates_repos():
        sources[r].add("crates")
    for org in sorted(set(ORGS)):
        for r in org_repos(org):
            sources[r].add("org")
    for t in REPO_TOPICS:
        for r in search("repositories", f"topic:{t}", 2.5):
            sources[r].add("topic")
    for q in REPO_QUERIES:
        for r in search("repositories", f"{q} language:rust", 2.5):
            sources[r].add("repo_search")
    for q in CODE_QUERIES:
        for r in search("code", q, 7.0):
            sources[r].add("code_search")
    return sources


def discover(cached: bool) -> None:
    """Gather (or reload) candidate sources, fetch metadata, filter by size/language, dedupe forks."""
    if cached:
        sources = {r: set(s) for r, s in json.load(open(SOURCES)).items()}
    else:
        sources = gather_sources()
        REPOS_DIR.mkdir(parents=True, exist_ok=True)
        json.dump({r: sorted(s) for r, s in sources.items()}, open(SOURCES, "w"))
    by_lower = {}
    for r, s in sources.items():
        if not REPO_NAME_RE.fullmatch(r):
            continue
        by_lower.setdefault(r.lower(), (r, set()))[1].update(s)
    print(f"raw candidates: {len(by_lower)}", file=sys.stderr)
    meta = fetch_meta([r for r, _ in by_lower.values()])
    srcs = {k: s for k, (_, s) in by_lower.items()}
    cands = {}
    for name, m in meta.items():
        s = srcs.get(name.lower(), set())
        m["sources"] = sorted(s)
        trusted = s & {"crates", "code_search"}
        if m["size_kb"] > MAX_KB or m["size_kb"] == 0 or not (trusted or "Rust" in m["languages"]):
            continue
        cands[name] = m
    keep = dedupe_forks(cands)
    REPOS_DIR.mkdir(parents=True, exist_ok=True)
    with open(CANDIDATES, "w") as f:
        for name in sorted(keep, key=str.lower):
            f.write(json.dumps(cands[name]) + "\n")
    print(f"metadata {len(meta)}, after size/language filter {len(cands)}, after fork dedupe {len(keep)}",
          file=sys.stderr)


# ---------- clone ----------

GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}


def git_out(path: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True, env=GIT_ENV).stdout.strip()


# Only Rust sources and Cargo manifests are checked out; history stays complete (blobs fetched lazily).
SPARSE = ["*.rs", "Cargo.toml", "Cargo.lock", "!**/target/**", "!**/node_modules/**"]


def run_git(args: list[str], timeout: int = 900) -> str | None:
    """Run git; None on success, else the error tail."""
    try:
        r = subprocess.run(["git", *args], capture_output=True, text=True, env=GIT_ENV, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "timeout"
    return None if r.returncode == 0 else (r.stderr.strip()[-300:] or f"exit {r.returncode}")


def clone_one(repo: str) -> tuple[str, str | None]:
    """Partial clone (no blobs up front) with a sparse checkout of Rust/Cargo files; re-sparsifies old clones."""
    dest = local_dir(repo)
    if (dest / ".git").exists():
        if git_out(dest, "config", "core.sparseCheckout") == "true":
            return repo, None
        return repo, (run_git(["-C", str(dest), "sparse-checkout", "set", "--no-cone", *SPARSE])
                      or run_git(["-C", str(dest), "checkout", "-f", "--quiet"]))
    shutil.rmtree(dest, ignore_errors=True)
    err = (run_git(["clone", "--filter=blob:none", "--no-checkout", "--quiet", f"https://github.com/{repo}.git", str(dest)])
           or run_git(["-C", str(dest), "sparse-checkout", "set", "--no-cone", *SPARSE])
           or run_git(["-C", str(dest), "checkout", "--quiet"]))
    if err:
        shutil.rmtree(dest, ignore_errors=True)
    return repo, err


def clone(workers: int) -> None:
    repos = [json.loads(line)["repo"] for line in open(CANDIDATES)]
    failed = {}
    with ThreadPoolExecutor(workers) as ex:
        for i, (repo, err) in enumerate(ex.map(clone_one, repos), 1):
            if err:
                failed[repo] = err
            if i % 50 == 0:
                print(f"cloned {i}/{len(repos)} failed {len(failed)}", file=sys.stderr, flush=True)
    with open(REPOS_DIR / ".clone_failed.json", "w") as f:
        json.dump(failed, f, indent=1)
    print(f"clone done: {len(repos) - len(failed)} ok, {len(failed)} failed", file=sys.stderr)


# ---------- index ----------

def scan_tree(root: Path) -> dict:
    """Walk a checkout: .rs count, .rs files using near_sdk, Cargo.toml and Cargo.lock texts."""
    rs, contract, tomls, locks = 0, [], [], []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for fn in files:
            p = Path(d) / fn
            rel = str(p.relative_to(root))
            if fn.endswith(".rs") or fn in ("Cargo.toml", "Cargo.lock"):
                try:
                    if p.is_symlink() or p.stat().st_size > 5_000_000:
                        continue
                    txt = p.read_text(errors="replace")
                except OSError:
                    continue
                if fn.endswith(".rs"):
                    rs += 1
                    if uses_near_sdk(txt):
                        contract.append(rel)
                elif fn == "Cargo.toml":
                    tomls.append(txt)
                else:
                    locks.append(txt)
    return {"n_rs": rs, "contract": contract, "tomls": tomls, "locks": locks}


def audited_repos() -> set[str]:
    """Repos named in audit findings written by the audits collector, if present."""
    out = set()
    for p in list(RAW.glob("audit_findings/*.jsonl")) + [RAW / "audit_findings.jsonl"]:
        if p.exists():
            for line in open(p):
                try:
                    r = repo_from_url(json.loads(line).get("repo"))
                except (json.JSONDecodeError, AttributeError):
                    continue
                if r:
                    out.add(r.lower())
    return out


def index_one(m: dict) -> dict | None:
    path = local_dir(m["repo"])
    if not (path / ".git").exists():
        return None
    t = scan_tree(path)
    return {"repo": m["repo"], "stars": m["stars"], "license": m["license"],
            "last_commit": git_out(path, "log", "-1", "--format=%cs") or m["last_commit"],
            "head_commit": git_out(path, "rev-parse", "HEAD"), "near_sdk_version": near_sdk_version(t["tomls"], t["locks"]),
            "fork_of": m["fork_of"], "audited": is_audited(git_out(path, "ls-tree", "-r", "--name-only", "HEAD").splitlines()), "local_path": str(path),
            "n_rs_files": t["n_rs"], "n_contract_rs_files": len(t["contract"]), "sources": m.get("sources", [])}


def index(workers: int, prune: bool) -> None:
    metas = [json.loads(line) for line in open(CANDIDATES)]
    audited = audited_repos()
    rows, dropped = [], []
    with ThreadPoolExecutor(workers) as ex:
        for m, row in zip(metas, ex.map(index_one, metas)):
            if row is None:
                continue
            if row["n_contract_rs_files"] == 0:
                dropped.append({"repo": m["repo"], "reason": "no .rs file uses near_sdk", "n_rs_files": row["n_rs_files"]})
                if prune:
                    shutil.rmtree(local_dir(m["repo"]), ignore_errors=True)
                continue
            row["audited"] = row["audited"] or row["repo"].lower() in audited
            rows.append(row)
    with open(REPOS_JSONL, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    with open(DROPPED, "w") as f:
        for r in dropped:
            f.write(json.dumps(r) + "\n")
    print(f"index: {len(rows)} repos, {sum(r['n_contract_rs_files'] for r in rows)} contract .rs files, "
          f"{sum(r['n_rs_files'] for r in rows)} .rs files; dropped {len(dropped)} without near_sdk", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["discover", "clone", "index"])
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--cached", action="store_true", help="discover: reuse .sources.json instead of searching")
    ap.add_argument("--no-prune", action="store_true", help="keep clones that have no near_sdk file")
    a = ap.parse_args()
    if a.step == "discover":
        discover(a.cached)
    elif a.step == "clone":
        clone(a.workers)
    else:
        index(a.workers, not a.no_prune)


if __name__ == "__main__":
    main()
