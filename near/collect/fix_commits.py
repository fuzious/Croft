"""Mine candidate security-fix commits from the cloned NEAR contract repos.

    uv run python -m near.collect.fix_commits      # -> near/data/raw/fix_commit_candidates.jsonl

A candidate is a non-merge commit (any branch) whose message matches a security keyword and that touches a .rs file
of a near-sdk crate. Candidates are noisy on purpose: the triage step decides which are real fixes.
"""
import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from near.collect.corpus import GIT_ENV, REPOS_JSONL, RAW, SKIP_DIRS, uses_near_sdk

OUT = RAW / "fix_commit_candidates.jsonl"
FIX_WORDS = ["overflow", "underflow", "reentr", "callback", "private", "yocto", "access", "owner", "auth", "signer",
             "storage", "rounding", "precision", "promise", "refund", "deposit", "withdraw", "panic", "gas"]
KEYWORDS = {
    "vuln": r"vuln", "exploit": r"exploit", "security": r"\bsecurity\b", "audit": r"\baudit", "cve": r"\bcve\b",
    "bounty": r"bounty", "hack": r"\bhack(?!athon|y|ish)", "attack": r"\battack", "drain": r"\bdrain",
    "critical": r"\bcritical\b", "high_severity": r"high[ -]severity|severity:?\s*high",
    **{f"fix_{w}": rf"\bfix\w*\b.*\b{w}" + (r"(?!or|ors\b)" if w == "auth" else r"(?!ib)" if w == "access" else "")
       for w in FIX_WORDS},
}
KEYWORD_RES = {k: re.compile(v, re.I) for k, v in KEYWORDS.items()}
# Coarse POSIX ERE prefilter for `git log --grep`; match_keywords applies the precise rules.
GREP = "vuln|exploit|secur|audit|cve|bounty|hack|attack|drain|critical|severity|fix"
SEP_C, SEP_F = "\x1e", "\x1f"


def match_keywords(message: str) -> list[str]:
    """Sorted security keyword labels found in a commit message."""
    return sorted(k for k, rx in KEYWORD_RES.items() if rx.search(message))


def is_contract_path(path: str, roots: set[str], contract_files: set[str]) -> bool:
    """A .rs file inside a near-sdk crate root ("" = repo root), or a file that used near_sdk at HEAD."""
    if not path.endswith(".rs"):
        return False
    if path in contract_files:
        return True
    return any(r == "" or path.startswith(r + "/") for r in roots)


def parse_log(out: str) -> list[dict]:
    """Parse `git log --format=<RS>%H<US>%P<US>%cs<US>%B<US> --name-only` output."""
    rows = []
    for chunk in out.split(SEP_C)[1:]:
        commit, parents, date, message, files = chunk.split(SEP_F, 4)
        rows.append({"commit": commit, "parent": parents.split()[0] if parents.split() else None, "date": date,
                     "message": message.strip(), "files": [f for f in files.split("\n") if f.strip()]})
    return rows


def git(path: str, *args: str, timeout: int = 600) -> str:
    r = subprocess.run(["git", "-C", path, *args], capture_output=True, text=True, env=GIT_ENV, timeout=timeout,
                       errors="replace")
    return r.stdout


def contract_scope(path: Path) -> tuple[set[str], set[str]]:
    """near-sdk crate roots (dirs whose Cargo.toml names near-sdk) and .rs files using near_sdk, at HEAD."""
    roots, files = set(), set()
    for p in path.rglob("*"):
        if any(part in SKIP_DIRS for part in p.relative_to(path).parts[:-1]) or p.is_symlink() or not p.is_file():
            continue
        rel = str(p.relative_to(path))
        try:
            if p.name == "Cargo.toml" and re.search(r"^\s*near-sdk\b", p.read_text(errors="replace"), re.M):
                d = str(p.parent.relative_to(path))
                roots.add("" if d == "." else d)
            elif p.suffix == ".rs" and p.stat().st_size < 5_000_000 and uses_near_sdk(p.read_text(errors="replace")):
                files.add(rel)
        except OSError:
            continue
    return roots, files


def lines_changed(path: str, commit: str, files: list[str]) -> int | None:
    """Added + deleted lines in the given files (fetches the blobs lazily in a partial clone)."""
    try:
        out = git(path, "show", "--numstat", "--format=", commit, "--", *files, timeout=300)
    except subprocess.TimeoutExpired:
        return None
    n = 0
    for line in out.splitlines():
        a, d, *_ = line.split("\t")
        n += int(a) + int(d) if a.isdigit() and d.isdigit() else 0
    return n


def mine_repo(row: dict, numstat: bool) -> list[dict]:
    path = row["local_path"]
    roots, files = contract_scope(Path(path))
    try:
        out = git(path, "log", "--all", "--no-merges", "-i", "-E", f"--grep={GREP}",
                  f"--format={SEP_C}%H{SEP_F}%P{SEP_F}%cs{SEP_F}%B{SEP_F}", "--name-only")
    except subprocess.TimeoutExpired:
        print(f"timeout: {row['repo']}", file=sys.stderr)
        return []
    cands = []
    for c in parse_log(out):
        kws = match_keywords(c["message"])
        touched = [f for f in c["files"] if is_contract_path(f, roots, files)]
        if not kws or not touched:
            continue
        cands.append({"repo": row["repo"], "commit": c["commit"], "parent": c["parent"], "date": c["date"],
                      "message": c["message"][:4000], "files": touched, "keywords": kws,
                      "n_lines_changed": lines_changed(path, c["commit"], touched) if numstat else None})
    return cands


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--no-numstat", action="store_true", help="skip n_lines_changed (no lazy blob fetches)")
    a = ap.parse_args()
    repos = [json.loads(line) for line in open(REPOS_JSONL)]
    # originals before forks, so a commit shared through history is credited to the source repo
    repos.sort(key=lambda r: (r["fork_of"] is not None, -(r["stars"] or 0)))
    seen, n = set(), 0
    with open(OUT, "w") as f, ThreadPoolExecutor(a.workers) as ex:
        for i, cands in enumerate(ex.map(lambda r: mine_repo(r, not a.no_numstat), repos), 1):
            for c in cands:
                if c["commit"] in seen:
                    continue
                seen.add(c["commit"])
                f.write(json.dumps(c) + "\n")
                n += 1
            if i % 50 == 0:
                print(f"mined {i}/{len(repos)} repos, {n} candidates", file=sys.stderr, flush=True)
    print(f"fix commit candidates: {n} from {len(repos)} repos", file=sys.stderr)


if __name__ == "__main__":
    main()
