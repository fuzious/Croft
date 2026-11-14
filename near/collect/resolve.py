"""Resolve real NEAR vulnerabilities (audit findings, incidents, triaged fix commits) into function-level samples.

Every function is extracted with near.analyzer.extract_functions from the file at the vulnerable commit (label 1)
and at the fix commit (label 0, linked by pair_id), so its text matches the corpus exactly. Files come from the
local partial clones (near/data/raw/repos, incidents/repos) or, for repos without one, from the GitHub tarball of
that commit (cached under near/data/raw/resolve_cache/; parsed only, never extracted to disk or built).

    uv run python -m near.collect.resolve            # -> near/data/real_samples.jsonl + real_samples_report.md
"""
from __future__ import annotations

import collections
import hashlib
import io
import json
import re
import subprocess
import tarfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from near.analyzer import extract_functions
from near.analyzer.rust_parse import PARSER

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "near" / "data" / "raw"
CACHE = RAW / "resolve_cache"
OUT = ROOT / "near" / "data" / "real_samples.jsonl"
REPORT = ROOT / "near" / "data" / "real_samples_report.md"
GIT_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
           "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}

SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "warning": "low",
            "info": "info", "informational": "info", "note": "info"}
WEIGHT = {"info": 0.3, "low": 0.6}
# Repos whose original is gone, mapped to the reachable copy of the same code (also used as the group, so the
# corpus copy and the labelled rows land in one group).
ALIASES = {"ref-finance/ref-contracts": "rozgo/ref-contracts", "devofcredit/ref-contracts": "rozgo/ref-contracts",
           "ref-finance/boost-farm": "cb-defi-notifs/ref-finance-boost-farm-98615845"}
SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
PR_RE = re.compile(r"github\.com/([^/]+/[^/]+)/pull/(\d+)")


def slug(url: str | None) -> str | None:
    """'owner/repo' from a GitHub/GitLab URL or 'gitlab:owner/repo'."""
    if not url:
        return None
    m = re.search(r"(?:github\.com|gitlab\.com)[:/]+([^/\s]+)/([^/\s#?]+)|^gitlab:([^/\s]+)/([^/\s]+)", url)
    if not m:
        return None
    owner, repo = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
    return f"{owner}/{repo.rstrip('/').removesuffix('.git')}"


def split_fn(name: str) -> tuple[str, str | None]:
    """'Type::method' -> ('method', 'Type'); strips a trailing '()'."""
    name = name.strip().removesuffix("()")
    if "::" in name:
        impl, _, fn = name.rpartition("::")
        return fn, impl.split("::")[-1]
    return name, None


def norm_severity(s: str | None) -> str | None:
    return SEVERITY.get((s or "").strip().lower())


def weight(sev: str | None) -> float:
    """Sample weight by finding severity (info 0.3, low 0.6, else 1)."""
    return WEIGHT.get(sev, 1.0)


def sample_id(group: str, path: str, fn: str, code: str) -> str:
    return hashlib.sha1(f"{group}|{path}|{fn}|{code}".encode()).hexdigest()


def _tokens(code: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+", code))


def _similarity(snippet: str, code: str) -> float:
    """Share of the snippet's tokens found in `code` (report snippets are often partial)."""
    ts = _tokens(snippet)
    return len(ts & _tokens(code)) / max(1, len(ts))


def pick(fns: list[dict], name: str, snippet: str | None = None, impl: str | None = None) -> tuple[dict | None, str]:
    """The one function called `name` (non-test preferred), disambiguated by impl, then by snippet similarity."""
    cands = [f for f in fns if f["fn"] == name]
    if not cands:
        return None, "fn_not_found"
    cands = [f for f in cands if not f.get("is_test")] or cands
    if impl and len(cands) > 1:
        cands = [f for f in cands if f["impl"] == impl or f.get("trait") == impl] or cands
    if len({f["code"] for f in cands}) == 1:
        return cands[0], "ok"
    if snippet:
        scored = sorted(((_similarity(snippet, f["code"]), i) for i, f in enumerate(cands)), reverse=True)
        if scored[0][0] >= 0.6 and scored[0][0] - scored[1][0] >= 0.05:
            return cands[scored[0][1]], "ok"
    return None, "ambiguous"


def agrees(code: str, snippet: str | None, name: str, searched: bool) -> bool:
    """Whether a located function is consistent with the report snippet: a snippet that quotes `fn name` must
    share most of its tokens; a snippet of other code only constrains functions found by tree search."""
    if not snippet:
        return True
    if re.search(rf"\bfn\s+{re.escape(name)}\b", snippet):
        return _similarity(snippet, code) >= 0.5
    return not searched or _similarity(snippet, code) >= 0.2


def snippet_function(snippet: str | None, name: str | None) -> dict | None:
    """The function in a report snippet when it parses as one complete, error-free function (named `name`)."""
    if not snippet:
        return None
    fns = [f for f in extract_functions(snippet, "") if name is None or f["fn"] == name]
    if len(fns) != 1 or PARSER.parse(fns[0]["code"].encode()).root_node.has_error:
        return None
    return fns[0]


def dedupe_findings(rows: list[dict]) -> tuple[list[dict], dict]:
    """Drop repeated findings (same repo/commit/path/fn/title) and findings of an overlapping report whose
    function is already covered by that report."""
    seen, by_report, kept = set(), collections.defaultdict(set), []
    dropped = collections.Counter()
    for r in rows:
        key = ((r.get("repo") or "").lower(), r.get("commit"), r.get("path"), r.get("fn"),
               (r.get("title") or "").strip().lower())
        if key in seen:
            dropped["duplicate_finding"] += 1
            continue
        seen.add(key)
        by_report[r["report"]].add(((r.get("repo") or "").lower(), r.get("fn")))
        kept.append(r)
    out = []
    for r in kept:
        o = r.get("overlaps_report")
        if o and o != r["report"] and ((r.get("repo") or "").lower(), r.get("fn")) in by_report.get(o, set()):
            dropped["overlapping_report"] += 1
            continue
        out.append(r)
    return out, dict(dropped)


def finalize(rows: list[dict]) -> tuple[list[dict], dict]:
    """Unique ids (first wins); label-0 rows whose exact code is also label 1 somewhere are dropped."""
    log = collections.Counter(duplicate_ids=0, label_conflicts=0)
    by_id = {}
    for r in rows:
        if r["id"] in by_id:
            log["duplicate_ids"] += 1
            continue
        by_id[r["id"]] = r
    vuln_code = {r["code"] for r in by_id.values() if r["label"] == 1}
    out = []
    for r in by_id.values():
        if r["label"] == 0 and r["code"] in vuln_code:
            log["label_conflicts"] += 1
            continue
        out.append(r)
    ids = {r["id"] for r in out}
    for r in out:
        if r.get("pair_id") and r["pair_id"] not in ids:
            r["pair_id"] = None
    return out, dict(log)


# ---------------------------------------------------------------- code access (local clones, GitHub tarballs)

def _git(clone: Path, *args: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """git in a partial clone; retried when a lazy blob fetch from the remote fails (transient network errors)."""
    for _ in range(3):
        p = subprocess.run(["git", "-C", str(clone), *args], capture_output=True, text=True, timeout=timeout,
                           env=GIT_ENV, errors="replace")
        if p.returncode == 0 or not re.search(r"fetch|promisor|remote|unable to read", p.stderr, re.I):
            return p
    return p


def _gh(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """gh CLI call; retried on server errors / rate limiting (404s and 422s are final)."""
    for _ in range(3):
        p = subprocess.run(["gh", *args], capture_output=True, timeout=timeout)
        if p.returncode == 0 or not re.search(rb"HTTP (5\d\d|429|403)|timeout|connection", p.stderr, re.I):
            return p
    return p


class Code:
    """Read files / search functions in a repo at a commit, through local clones or GitHub tarballs."""

    def __init__(self):
        self.local = {}
        for line in (RAW / "repos.jsonl").read_text().splitlines():
            r = json.loads(line)
            self.local[r["repo"].lower()] = ROOT / r["local_path"]
        for d in (RAW / "incidents" / "repos").glob("*"):
            url = _git(d, "remote", "get-url", "origin").stdout.strip()
            if slug(url):
                self.local.setdefault(slug(url).lower(), d)
        self.lock = threading.Lock()
        self.meta_path = CACHE / "repo_meta.json"
        self.meta = json.loads(self.meta_path.read_text()) if self.meta_path.exists() else {}
        self.trees: dict = {}

    def repo_meta(self, s: str) -> dict:
        """{'name': canonical full name or None if unreachable, 'root': fork-network source}."""
        k = s.lower()
        if k not in self.meta:
            p = _gh("api", f"repos/{s}", "--jq", "[.full_name, (.source.full_name // .full_name)]|@tsv")
            name, root = (p.stdout.decode().strip().split("\t") + [None])[:2] if p.returncode == 0 else (None, None)
            with self.lock:
                self.meta[k] = {"name": name, "root": root}
                CACHE.mkdir(parents=True, exist_ok=True)
                self.meta_path.write_text(json.dumps(self.meta, indent=1, sort_keys=True))
        return self.meta[k]

    def group(self, s: str) -> str:
        """Leakage-safe group: fork-network root of the canonical repo, aliases for vanished originals."""
        k = s.lower()
        if k in ALIASES:
            return ALIASES[k]
        m = self.repo_meta(s)
        return (m["root"] or k).lower()

    def sources(self, slugs: list[str]) -> list[tuple[str, object]]:
        """Candidate code sources in order: local clones, then reachable GitHub repos (tarball)."""
        names = []
        for s in slugs:
            for n in (s, ALIASES.get(s.lower()), self.repo_meta(s)["name"]):
                if n and n.lower() not in [x.lower() for x in names]:
                    names.append(n)
        local = [("git", self.local[n.lower()]) for n in names if n.lower() in self.local
                 and self.local[n.lower()].exists()]
        remote = [("tar", n) for n in names if self.repo_meta(n)["name"]]
        return local + remote

    def tree(self, src: tuple, sha: str) -> dict | None:
        """{'sha': full sha, 'files': {path: text} (tarball) or None (git)} for a commit, or None if absent."""
        key = (src[0], str(src[1]), sha)
        if key in self.trees:
            return self.trees[key]
        out = None
        if src[0] == "git":
            p = _git(src[1], "rev-parse", "--verify", "-q", f"{sha}^{{commit}}")
            if p.returncode == 0:
                out = {"sha": p.stdout.strip(), "files": None, "clone": src[1]}
        else:
            out = self._tarball(src[1], sha)
        self.trees[key] = out
        return out

    def _tarball(self, s: str, sha: str) -> dict | None:
        """The .rs files of `s` at `sha` from the GitHub tarball (cached; read in memory, never extracted)."""
        if len(sha) < 40:
            p = _gh("api", f"repos/{s}/commits/{sha}", "--jq", ".sha")
            if p.returncode != 0 or not p.stdout.strip():
                return None
            sha = p.stdout.decode().strip()
        f = CACHE / "tarballs" / f"{s.replace('/', '__')}__{sha}.tar.gz"
        if not f.exists():
            p = _gh("api", f"repos/{s}/tarball/{sha}", timeout=600)
            if p.returncode != 0 or not p.stdout:
                return None
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(p.stdout)
        files = {}
        with tarfile.open(fileobj=io.BytesIO(f.read_bytes()), mode="r:gz") as tar:
            for m in tar:
                if m.isfile() and m.name.endswith(".rs") and "/" in m.name:
                    files[m.name.split("/", 1)[1]] = tar.extractfile(m).read().decode("utf8", errors="replace")
        return {"sha": sha, "files": files}

    def read(self, t: dict, path: str) -> str | None:
        if t["files"] is not None:
            return t["files"].get(path)
        p = _git(t["clone"], "show", f"{t['sha']}:{path}")
        return p.stdout if p.returncode == 0 else None

    def find(self, t: dict, name: str) -> list[str]:
        """.rs paths at the commit that define `fn name`."""
        rx = re.compile(rf"\bfn\s+{re.escape(name)}\b")
        if t["files"] is not None:
            return sorted(p for p, s in t["files"].items() if rx.search(s))
        p = _git(t["clone"], "grep", "-l", "-E", rf"fn[[:space:]]+{name}([^A-Za-z0-9_]|$)", t["sha"], "--", "*.rs")
        return sorted(line.split(":", 1)[1] for line in p.stdout.splitlines() if ":" in line)


def resolve_ref(ref: str | None) -> list[tuple[str | None, str]]:
    """A commit field -> [(repo slug override or None, sha-or-ref)]: PR URLs become their merge/head commit."""
    if not ref:
        return []
    out = []
    for part in [x.strip() for x in ref.split(",") if x.strip()]:
        m = PR_RE.search(part)
        if m:
            p = _gh("api", f"repos/{m.group(1)}/pulls/{m.group(2)}", "--jq",
                    "(.merge_commit_sha // .head.sha) + \"\\t\" + (.merged|tostring)")
            if p.returncode == 0 and p.stdout.strip():
                out.append((m.group(1), p.stdout.decode().split("\t")[0].strip()))
        elif SHA_RE.match(part.lower()):
            out.append((None, part.lower()))
    return out[-1:]  # the last listed fix commit is the final fixed state


def locate(code: Code, slugs: list[str], sha: str, path: str | None, name: str, snippet: str | None = None,
           impl: str | None = None, check: bool = True) -> tuple[dict | None, dict | None, str]:
    """(fn record, tree info, reason) for `name` at `sha`: the given path first, else a unique match in the tree.
    With `check`, a function that disagrees with the report snippet is rejected (see agrees)."""
    reason = "commit_unavailable"
    for src in code.sources(slugs):
        t = code.tree(src, sha)
        if t is None:
            continue
        if path and path.endswith(".rs"):
            text = code.read(t, path)
            if text is not None:
                rec, reason = pick(extract_functions(text, path), name, snippet, impl)
                if rec and (not check or agrees(rec["code"], snippet, name, searched=False)):
                    return rec, {**t, "src": src}, "ok"
        hits, why = code.find(t, name), "not_found"
        base = [h for h in hits if path and h.rsplit("/", 1)[-1] == path.rsplit("/", 1)[-1]]
        # a basename/stale path from the report narrows the search first; then the whole tree
        for scope in [x for x in (base, hits) if x]:
            cands = []  # test code is never a search result (e.g. fixtures of macro-generated methods)
            for h in scope:
                cands += [f for f in extract_functions(code.read(t, h) or "", h) if f["fn"] == name
                          and not f["is_test"]]
            rec, why = pick(cands, name, snippet, impl)
            if rec and check and not agrees(rec["code"], snippet, name, searched=True):
                rec, why = None, "snippet_mismatch"
            if rec:
                return rec, {**t, "src": src}, "ok_tree_search"
        return None, t, {"ambiguous": "fn_ambiguous", "snippet_mismatch": "snippet_mismatch"}.get(why, "fn_not_found")
    return None, None, reason


# ---------------------------------------------------------------- rows per source

def make_row(rec: dict, *, label: int, group: str, **fields) -> dict:
    row = {"id": sample_id(group, rec["path"], rec["fn"], rec["code"]), "code": rec["code"], "fn": rec["fn"],
           "impl": rec["impl"], "is_near_bindgen": rec["is_near_bindgen"], "attrs": rec["attrs"], "label": label,
           "vuln_class": None, "severity": None, "source": None, "group": group, "repo": None, "commit": None,
           "path": rec["path"], "date": None, "evidence": None, "pair_id": None}
    row.update(fields)
    if label == 0:
        row["vuln_class"] = None
    return row


def _pair(code: Code, slugs, vuln: dict, vrow: dict, fix_ref, name, impl, extra: dict) -> tuple[list[dict], str]:
    """The fixed counterpart of a vulnerable row (label 0, pair_id both ways), or a reason it is absent."""
    refs = resolve_ref(fix_ref)
    if not refs:
        return [], "no_fix_commit" if not fix_ref else "fix_ref_unresolved"
    override, sha = refs[0]
    rec, t, why = locate(code, ([override] if override else []) + slugs, sha, vuln["path"], name, vuln["code"],
                         impl or vuln["impl"], check=False)
    if rec is None:
        return [], f"fix_{why}"
    if rec["code"] == vuln["code"]:
        return [], "fix_identical"
    frow = make_row(rec, label=0, group=vrow["group"], **{**extra, "commit": t["sha"], "pair_id": vrow["id"]})
    vrow["pair_id"] = frow["id"]
    return [frow], "paired"


def resolve_audit(code: Code, f: dict) -> tuple[list[dict], str, str]:
    """(rows, status of the vulnerable side, status of the fixed side) for one finding."""
    s = slug(f.get("repo"))
    on_github = bool(s) and "github.com" in f["repo"]
    sev = norm_severity(f.get("severity"))
    project = re.sub(r"[^a-z0-9]+", "-", f["project"].lower()).strip("-")
    group = (code.group(s) if on_github else s.lower()) if s else project
    base = {"severity": sev, "source": "audit", "repo": f"https://github.com/{s}" if on_github else f.get("repo"),
            "date": f.get("date"), "evidence": f.get("url"),
            "weight": weight(sev), "code_from_snippet": False, "finding": f.get("title"), "report": f.get("report")}
    name, impl = split_fn(f["fn"]) if f.get("fn") else (None, None)
    slugs = [x for x in (s if on_github else None, slug(f.get("repo_mirror"))) if x]
    status = ("no_fn" if not name else "repo_not_on_github" if s and not slugs else "no_repo" if not slugs
              else "no_commit" if not f.get("commit") else None)
    rec = t = None
    if status is None:
        rec, t, status = locate(code, slugs, f["commit"], f.get("path"), name, f.get("snippet"), impl)
    if rec is not None:
        vrow = make_row(rec, label=1, group=group, **base, vuln_class=f["vuln_class"], commit=t["sha"],
                        fetched_from=str(t["src"][1].name if t["src"][0] == "git" else t["src"][1]))
        fixed, fstatus = _pair(code, slugs, rec, vrow, f.get("fixed_commit"), name, impl,
                               {**base, "fetched_from": vrow["fetched_from"]})
        return [vrow, *fixed], status, fstatus
    srec = snippet_function(f.get("snippet"), name)
    if srec:
        srec = {**srec, "path": f.get("path") or ""}
        return [make_row(srec, label=1, group=group, **{**base, "code_from_snippet": True},
                         vuln_class=f["vuln_class"], commit=f.get("commit"))], f"snippet({status})", "none"
    return [], status, "none"


def resolve_incident(code: Code, i: dict) -> tuple[list[dict], str, str]:
    if i.get("rust") is False:
        return [], "not_rust", "none"
    if not (i.get("repo") and i.get("vuln_commit") and i.get("fn")):
        return [], "no_vuln_commit" if i.get("repo") and i.get("fn") else "no_code_ref", "none"
    s = slug(i["repo"])
    base = {"severity": None, "source": "incident", "kind": i.get("kind"), "confidence": i.get("confidence"),
            "repo": f"https://github.com/{s}", "date": i.get("date"), "evidence": (i.get("sources") or [None])[0],
            "weight": 1.0, "code_from_snippet": False, "finding": i["name"], "report": None}
    rec, t, status = locate(code, [s], i["vuln_commit"], i.get("path"), i["fn"], i.get("snippet"))
    if rec is None:
        return [], status, "none"
    vrow = make_row(rec, label=1, group=code.group(s), **base, vuln_class=i.get("vuln_class"), commit=t["sha"],
                    fetched_from=str(t["src"][1].name if t["src"][0] == "git" else t["src"][1]))
    fixed, fstatus = _pair(code, [s], rec, vrow, i.get("fix_commit"), i["fn"], rec["impl"],
                           {**base, "fetched_from": vrow["fetched_from"]})
    return [vrow, *fixed], status, fstatus


def resolve_fix_commit(code: Code, c: dict) -> tuple[list[dict], str, str]:
    """Each triaged vulnerable fn changed by the commit: parent version label 1, commit version label 0."""
    s, rows = c["repo"], []
    group = code.group(s)
    src = ("git", code.local[s.lower()])
    tp, tc = code.tree(src, c["parent"]), code.tree(src, c["commit"])
    if tp is None or tc is None:
        return [], "commit_unavailable", "none"
    base = {"severity": norm_severity(c.get("severity_guess")), "source": "fix_commit",
            "repo": f"https://github.com/{s}", "date": c.get("date"), "evidence": c.get("evidence")
            or f"https://github.com/{s}/commit/{c['commit']}", "code_from_snippet": False,
            "finding": c["message"].splitlines()[0][:200], "report": None, "fetched_from": src[1].name,
            "confidence": c.get("confidence")}
    base["weight"] = weight(base["severity"])
    fixed_n = 0
    for path in [p for p in c["files"] if p.endswith(".rs")]:
        before = {(f["impl"], f["fn"]): f for f in extract_functions(code.read(tp, path) or "", path)
                  if f["fn"] in c["fns"] and not f["is_test"]}
        after = {(f["impl"], f["fn"]): f for f in extract_functions(code.read(tc, path) or "", path)
                 if f["fn"] in c["fns"] and not f["is_test"]}
        for key, v in before.items():
            a = after.get(key)
            if a is not None and a["code"] == v["code"]:
                continue  # this fn was not touched by the fix
            vrow = make_row(v, label=1, group=group, **base, vuln_class=c["vuln_class"], commit=tp["sha"])
            rows.append(vrow)
            if a is not None:
                frow = make_row(a, label=0, group=group, **base, commit=tc["sha"], pair_id=vrow["id"])
                vrow["pair_id"] = frow["id"]
                rows.append(frow)
                fixed_n += 1
    if not rows:
        return [], "fn_not_changed", "none"
    return rows, "ok", "paired" if fixed_n else "fix_fn_removed"


# ---------------------------------------------------------------- driver and report

def load_audits() -> list[dict]:
    rows = []
    for f in sorted((RAW / "audit_findings").glob("*.jsonl")):
        if not f.name.endswith("_manifest.jsonl"):
            rows += [json.loads(line) for line in f.read_text().splitlines() if line.strip()]
    return rows


def _by_repo(items: list[dict], key) -> list[list[dict]]:
    groups = collections.defaultdict(list)
    for it in items:
        groups[key(it)].append(it)
    return list(groups.values())


def run_all(code: Code, items: list[dict], fn, key, workers: int = 16) -> list[tuple[dict, tuple]]:
    """Resolve items with one worker per repo (git lazy fetches into a clone stay sequential)."""
    def work(batch):
        out = []
        for it in batch:
            try:
                out.append((it, fn(code, it)))
            except Exception as e:  # keep going; the reason is reported
                out.append((it, ([], f"error:{type(e).__name__}", "none")))
        return out
    with ThreadPoolExecutor(workers) as ex:
        return [r for batch in ex.map(work, _by_repo(items, key)) for r in batch]


def write_report(results: dict, dedupe_drops: dict, final: list[dict], log: dict, n_raw: dict) -> str:
    lines = ["# Real NEAR vulnerability samples (near/data/real_samples.jsonl)", "",
             "Built by `uv run python -m near.collect.resolve`. Code extracted only through "
             "`near.analyzer.extract_functions` at the stated commits (local clones, else GitHub tarballs).", "",
             f"Rows: **{len(final)}** (label 1: {sum(r['label'] for r in final)}, label 0: "
             f"{sum(1 - r['label'] for r in final)}), groups: {len({r['group'] for r in final})}, "
             f"pairs: {sum(1 for r in final if r['label'] == 1 and r['pair_id'])}, "
             f"from report snippets: {sum(1 for r in final if r.get('code_from_snippet'))}.", "",
             f"Finalize: {log}. Audit dedupe before resolution: {dedupe_drops}.", "",
             "## Resolution per source", "", "| source | raw | after dedupe | resolved (label 1 from repo) | "
             "from snippet | dropped | rate |", "|---|---|---|---|---|---|---|"]
    for src, res in results.items():
        st = collections.Counter(r[1][1] for r in res)
        ok = st["ok"] + st["ok_tree_search"]
        snip = sum(v for k, v in st.items() if k.startswith("snippet"))
        lines.append(f"| {src} | {n_raw[src]} | {len(res)} | {ok} | {snip} | {len(res) - ok - snip} | "
                     f"{(ok + snip) / max(1, len(res)):.1%} |")
    lines += ["", "## Vulnerable-side status by reason (snippet(x) = kept from snippet after failing with x)", ""]
    for src, res in results.items():
        st = collections.Counter(r[1][1] for r in res)
        lines.append(f"- **{src}**: " + ", ".join(f"{k} {v}" for k, v in st.most_common()))
    lines += ["", "## Fixed-side status (label 0 counterpart)", ""]
    for src, res in results.items():
        st = collections.Counter(r[1][2] for r in res if r[1][0])
        lines.append(f"- **{src}**: " + ", ".join(f"{k} {v}" for k, v in st.most_common()))
    lines += ["", "## Final rows: source x label x vuln_class", "", "| source | label | vuln_class | rows |",
              "|---|---|---|---|"]
    c = collections.Counter((r["source"], r["label"], r["vuln_class"] or "-") for r in final)
    lines += [f"| {s} | {lb} | {v} | {n} |" for (s, lb, v), n in sorted(c.items(), key=lambda x: (x[0][0], -x[0][1],
                                                                                                    -x[1]))]
    lines += ["", "## Label-1 rows by severity (weight)", ""]
    c = collections.Counter((r["severity"] or "-", r["weight"]) for r in final if r["label"] == 1)
    lines.append(", ".join(f"{s} ({w}): {n}" for (s, w), n in sorted(c.items())))
    lines += ["", "## Largest groups", ""]
    c = collections.Counter(r["group"] for r in final)
    lines.append(", ".join(f"{g} {n}" for g, n in c.most_common(25)))
    lines += ["", "## Group aliases (vanished originals -> reachable copy)", "",
              "group = lower-case fork-network root of the canonical GitHub repo (redirects followed), so forks and "
              "mirrors share one group (e.g. ref-finance/burrowland -> neardefi/burrowland). Originals that are gone:"]
    lines += [f"- {a} -> {b}" for a, b in ALIASES.items()]
    lines += ["", "## Notes and limits", "",
              "- label 0 rows are the same function at the fix commit: fixed for that finding, not proven safe.",
              "- `code_from_snippet=true` rows come from the report text (repo private/deleted or commit gone); their "
              "whitespace/indentation differs from corpus extraction, and `commit` is the report's, unverified.",
              "- Tree search (path missing or stale) accepts only a unique non-test match, or a snippet-disambiguated "
              "one; a located function whose report snippet quotes `fn <name>` must share >= 50% of its tokens.",
              "- `weight`: info 0.3, low 0.6, medium/high/critical/unknown 1.0. Fixed rows carry their finding's "
              "weight. Fix-commit severity is the triage guess; incident severity is null.",
              "- Duplicate ids (several findings on one function) keep the first row: incidents, then audits, then "
              "fix commits; its vuln_class is that first finding's.",
              "- Fix commits: only the triaged `fns` that the commit changed are labelled; other changed functions "
              "are ignored. A fn with the same name in several changed files/impls yields one row each.",
              "- Per-item statuses: near/data/raw/resolve_cache/resolve_log.jsonl."]
    return "\n".join(lines) + "\n"


def main() -> None:
    code = Code()
    audits_raw = load_audits()
    audits, dedupe_drops = dedupe_findings(audits_raw)
    incidents = [json.loads(x) for x in (RAW / "incidents.jsonl").read_text().splitlines() if x.strip()]
    fixes = [json.loads(x) for x in (RAW / "fix_commits.jsonl").read_text().splitlines() if x.strip()]
    results = {
        "incident": run_all(code, incidents, resolve_incident, lambda i: (i.get("repo") or "").lower()),
        "audit": run_all(code, audits, resolve_audit, lambda f: (f.get("repo") or "").lower()),
        "fix_commit": run_all(code, fixes, resolve_fix_commit, lambda c: c["repo"].lower()),
    }
    rows = [row for res in results.values() for _, (rs, _, _) in res for row in rs]
    final, log = finalize(rows)
    OUT.write_text("".join(json.dumps(r) + "\n" for r in final))
    n_raw = {"incident": len(incidents), "audit": len(audits_raw), "fix_commit": len(fixes)}
    REPORT.write_text(write_report(results, dedupe_drops, final, log, n_raw))
    with (CACHE / "resolve_log.jsonl").open("w") as fh:
        for src, res in results.items():
            for it, (rs, st, fst) in res:
                fh.write(json.dumps({"source": src, "status": st, "fix_status": fst, "rows": len(rs),
                                     "item": {k: it.get(k) for k in ("report", "name", "title", "repo", "commit",
                                                                     "path", "fn", "fixed_commit", "fix_commit",
                                                                     "parent", "fns")}}) + "\n")
    print(f"{len(final)} rows -> {OUT}\n{log}\nreport -> {REPORT}")


if __name__ == "__main__":
    main()
