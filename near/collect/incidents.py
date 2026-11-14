"""NEAR security incidents: the curated list (near/data/raw/incidents/curated.json) -> incidents.jsonl.

Each curated entry names the repo, vulnerable commit, file and function; this module fetches that file at the
vulnerable commit (local clone under incidents/repos/ when it has the commit, else `gh api`) and stores the
function's source as `snippet`, extracted with near.analyzer so it matches the other sources' function text.

    uv run python -m near.collect.incidents
"""
import base64
import json
import subprocess
from pathlib import Path

from near.analyzer import extract_functions

RAW = Path(__file__).resolve().parents[1] / "data" / "raw"
CURATED = RAW / "incidents" / "curated.json"
REPOS = RAW / "incidents" / "repos"
OUT = RAW / "incidents.jsonl"

FIELDS = ["name", "date", "project", "loss_usd", "vuln_class", "summary", "repo", "vuln_commit", "fix_commit",
          "path", "fn", "snippet", "sources", "rust", "confidence", "kind", "notes"]


def pick_function(src: str, path: str, fn: str, impl: str | None = None, contains: str | None = None) -> str | None:
    """Source of function `fn` (optionally inside `impl`, optionally containing `contains`), or None."""
    for f in extract_functions(src, path):
        if f["fn"] == fn and (impl is None or f["impl"] == impl) and (contains is None or contains in f["code"]):
            return f["code"]
    return None


def _local_clone(repo: str) -> Path | None:
    for d in REPOS.glob("*"):
        url = subprocess.run(["git", "-C", str(d), "remote", "get-url", "origin"],
                             capture_output=True, text=True).stdout.strip()
        if url.removesuffix(".git").lower() == repo.lower():
            return d
    return None


def fetch_file(repo: str, sha: str, path: str) -> str | None:
    """File content at a commit: local clone first, then the GitHub contents API."""
    clone = _local_clone(repo) if REPOS.exists() else None
    if clone:
        r = subprocess.run(["git", "-C", str(clone), "show", f"{sha}:{path}"], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout
    slug = repo.removeprefix("https://github.com/")
    r = subprocess.run(["gh", "api", f"repos/{slug}/contents/{path}?ref={sha}", "--jq", ".content"],
                       capture_output=True, text=True)
    return base64.b64decode(r.stdout).decode() if r.returncode == 0 else None


def build_row(entry: dict, fetch=fetch_file) -> dict:
    """One incidents.jsonl row: the curated fields plus the vulnerable function's source (Rust only)."""
    snippet = None
    if entry["rust"] and entry["vuln_commit"] and entry["path"] and entry["fn"]:
        src = fetch(entry.get("mirror") or entry["repo"], entry["vuln_commit"], entry["path"])
        if src:
            snippet = pick_function(src, entry["path"], entry["fn"], entry.get("impl"), entry.get("contains"))
    return {k: snippet if k == "snippet" else entry.get(k) for k in FIELDS}


def main():
    rows = [build_row(e) for e in json.loads(CURATED.read_text())]
    OUT.write_text("".join(json.dumps(r) + "\n" for r in rows))
    located = [r for r in rows if r["snippet"]]
    missing = [r["name"] for r in rows if r["rust"] and r["vuln_commit"] and not r["snippet"]]
    print(f"{len(rows)} incidents, {sum(bool(r['rust']) for r in rows)} Rust, {len(located)} with code -> {OUT}")
    if missing:
        print("snippet not found for:", *missing, sep="\n  ")


if __name__ == "__main__":
    main()
