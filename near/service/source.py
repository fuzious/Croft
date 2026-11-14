"""Contract source for a NEAR account: NEP-330 `contract_source_metadata` -> GitHub repo + commit -> the repo's
tarball for that commit -> {path: rust source}. The tarball is untrusted: it is read in memory with size caps, only
regular `.rs` and `Cargo.toml` files are kept, nothing is written to disk or executed."""
from __future__ import annotations

import io
import re
import tarfile
import time
from collections import OrderedDict

import httpx

MAX_TARBALL_BYTES = 20 * 1024 * 1024   # compressed download cap
MAX_FILE_BYTES = 256 * 1024            # per file (scoring cost grows with file size x functions in it)
MAX_TOTAL_BYTES = 8 * 1024 * 1024      # all kept files together (decompressed)
MAX_FILES = 5000
SKIP_DIRS = {"target", ".git", "node_modules", "vendor"}
# test, mock, example and bench code is not the deployed contract; mock crates would otherwise drive the risk
NOT_DEPLOYED_DIR = re.compile(r"^(?:tests?|examples?|benches|mocks?|mock[-_].*|.*[-_]mocks?|.*[-_]tests?"
                              r"|integration[-_]tests?|sandbox[-_]tests?|test[-_]utils?)$", re.I)
CACHE_TTL_S = 6 * 3600
MAX_CACHE_ENTRIES = 16

_SHA = re.compile(r"^[0-9a-f]{7,40}$")
_GH = re.compile(r"^(?:git\+)?https://github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?"
                 r"(?:/(?:tree|commit|blob)/([^/?#]+))?/?(?:\?rev=([^&#]+))?(?:[#/].*)?$")
_cache: OrderedDict = OrderedDict()


class SourceError(Exception):
    pass


def _remember(key, files) -> None:
    """Cache a fetched tarball's files; least recently stored entries go first past MAX_CACHE_ENTRIES."""
    _cache[key] = (time.time() + CACHE_TTL_S, files)
    _cache.move_to_end(key)
    while len(_cache) > MAX_CACHE_ENTRIES:
        _cache.popitem(last=False)


def _parse_url(url) -> dict | None:
    m = _GH.match(url) if isinstance(url, str) else None
    if not m or m.group(2) in (".", ".."):
        return None
    ref = m.group(4) or m.group(3)
    return {"owner": m.group(1), "repo": m.group(2), "rev": ref.lower() if ref and _SHA.match(ref.lower()) else None}


def parse_source_metadata(meta) -> dict | None:
    """NEP-330 metadata -> {owner, repo, rev, contract_path, url, version}, or None when there is no GitHub repo.
    `build_info.source_code_snapshot` (git+https://github.com/o/r?rev=SHA) wins over `link`. `rev` is None unless
    it is a commit hash: a branch or tag can move, so it does not pin the deployed code."""
    if not isinstance(meta, dict):
        return None
    bi = meta.get("build_info") if isinstance(meta.get("build_info"), dict) else {}
    snap, link = _parse_url(bi.get("source_code_snapshot")), _parse_url(meta.get("link"))
    p = snap if snap and (snap["rev"] or not link) else link or snap
    if not p:
        return None
    path = bi.get("contract_path")
    return {**p, "contract_path": path.strip("/") if isinstance(path, str) and path.strip("/") else None,
            "url": f"https://github.com/{p['owner']}/{p['repo']}",
            "version": meta.get("version") if isinstance(meta.get("version"), str) else None}


def rust_files_from_tarball(data: bytes, contract_path: str | None = None) -> dict[str, str]:
    """{path: text} of regular .rs and Cargo.toml files in a GitHub tarball (top directory stripped; the v2 model reads
    the Cargo.toml chain, e.g. overflow-checks). With `contract_path`, only
    files under it, unless it holds none."""
    files, total = {}, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for m in tf:
                parts = m.name.split("/")
                if (not m.isreg() or m.name.startswith("/") or ".." in parts or len(parts) < 2
                        or not (m.name.endswith(".rs") or parts[-1] == "Cargo.toml") or SKIP_DIRS & set(parts[1:-1]) or m.size > MAX_FILE_BYTES
                        or any(NOT_DEPLOYED_DIR.match(d) for d in parts[1:-1])):
                    continue
                total += m.size
                if total > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
                    break
                files["/".join(parts[1:])] = tf.extractfile(m).read().decode("utf8", errors="replace")
    except (tarfile.TarError, OSError, EOFError) as e:
        raise SourceError(f"unreadable tarball: {e}") from None
    if contract_path:
        sub = {p: s for p, s in files.items() if p.startswith(contract_path.rstrip("/") + "/")}
        files = sub or files
    return files


def fetch_github_rust(owner: str, repo: str, rev: str | None, contract_path: str | None = None,
                      timeout: float = 30.0) -> dict[str, str]:
    """Download the repo tarball at `rev` (default branch when None) and return its .rs files. Cached in-process."""
    key = (owner, repo, rev or "HEAD", contract_path)
    hit = _cache.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{rev or 'HEAD'}"
    buf = bytearray()
    try:
        with httpx.stream("GET", url, timeout=timeout, follow_redirects=True) as r:
            if r.status_code == 404:
                raise SourceError(f"repository {owner}/{repo} at {rev or 'HEAD'} is not public on GitHub (HTTP 404)")
            if r.status_code != 200:
                raise SourceError(f"GitHub tarball HTTP {r.status_code}")
            for chunk in r.iter_bytes():
                buf += chunk
                if len(buf) > MAX_TARBALL_BYTES:
                    raise SourceError(f"repository tarball exceeds {MAX_TARBALL_BYTES // 2**20} MB")
    except httpx.HTTPError as e:
        raise SourceError(f"GitHub download failed: {type(e).__name__}") from None
    files = rust_files_from_tarball(bytes(buf), contract_path)
    _remember(key, files)
    return files


def contract_source(cfg: dict, account_id: str) -> dict:
    """{files, origin: nep330|none, verified, repo, rev, contract_path, error}. `verified` means the source is
    pinned to a commit by the contract's own NEP-330 metadata (not that the wasm was rebuilt and compared)."""
    from .signals import call_view

    out = {"files": {}, "origin": "none", "verified": False, "repo": None, "rev": None, "contract_path": None,
           "error": None}
    meta, err = call_view(cfg, account_id, "contract_source_metadata", {})
    if err:
        # the view's error text can come from the contract itself (a panic message): never pass it on
        out["error"] = ("no NEP-330 contract_source_metadata" if "MethodNotFound" in err
                        else "contract_source_metadata view failed")
        return out
    p = parse_source_metadata(meta)
    if not p:
        out["error"] = "NEP-330 metadata has no GitHub repository"
        return out
    out.update(origin="nep330", repo=p["url"], rev=p["rev"], contract_path=p["contract_path"])
    try:
        out["files"] = fetch_github_rust(p["owner"], p["repo"], p["rev"], p["contract_path"])
    except SourceError as e:
        out["error"] = str(e)
        return out
    if not out["files"]:
        out["error"] = "repository has no Rust files"
    out["verified"] = bool(p["rev"] and out["files"])
    return out
