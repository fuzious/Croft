"""File context for one function: signals from the rest of its source file and its Cargo manifests, plus
per-detector hits.

The same function computes the features in training and at inference. Training reads the files from the local clone
at the row's commit (`git_files`, offline, GIT_NO_LAZY_FETCH=1). Inference passes the `files` dict that
`near.model.predict.score_source` already has (`source_context`). In both cases the files that count are picked by
`scope_paths` from the file names alone: the function's own .rs file and every Cargo.toml from its directory up to
the repository root. With `crate=True`, the scope is the whole crate instead: the nearest ancestor directory holding
a Cargo.toml, with its non-test .rs files, sorted, and at most MAX_FILES of them. The model does not use the crate
scope, because the local clones are partial. Sibling files of old commits are often missing offline: 40% of real
train rows lack at least one, while no corpus or mutation row does. Crate-wide counts would then tell real rows from
corpus rows by how complete their clone is. A Cargo.toml missing at an old commit is read from HEAD in training
(train_classic_v2._ctx_job).
When the file itself is not available, the context is the function alone (`files = {path: code}`). Training excludes
those rows, because only real positives lack their file.

In the feature names, "crate" means that scope: the function's file.
Features (CONTEXT_KEYS, stable order):
- callbacks this function schedules on its own contract (Self::ext(..).cb(), ext_self::cb(), ...), resolved by name
  in the crate: how many have no #[private] or predecessor == current_account_id check, and how many never read the
  promise result;
- whether this function is itself scheduled as a callback somewhere in the crate, and whether it is unprotected;
- owner pattern: the crate has an owner/admin AccountId field, and auth helpers (other functions that compare the
  predecessor with an owner/admin or with a stored account). Records whether this function calls one of those
  helpers, and whether it is a mutating entry point of a contract that has them but calls none;
- inconsistency (as in Rustle): among the other mutating entry points of the crate, and among those with similar
  names, the share that check the predecessor or auth, assert one yocto, or are #[private], times 1 when this
  function lacks the same check;
- callers: other crate functions that call this one by name, and how many of them are unauthenticated mutating
  entry points;
- file and manifest facts: overflow-checks in [profile.release], near-sdk major.minor version, number of functions
  and lines.

`detector_counts` gives one count per analyzer detector (not only per vuln_class), with the file passed to the
analyzer so callback detection sees the scheduling code.
"""
from __future__ import annotations

import math
import os
import posixpath
import re
import subprocess

from near.analyzer import detect, extract_functions
from near.analyzer.detectors import (AUTH_COMPARE, AUTH_HELPER, CALLBACK_ATTRS, PROMISE_RESULT, SELF_CHECK, YOCTO,
                                     _compared, callback_names, context, overflow_checks_enabled, strip_code)
from near.model.eval_common import TEST_PATH

MAX_FILES = 200
MAX_FILE_BYTES = 1 << 20
GIT_ENV = {"GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0", "PATH": os.environ.get("PATH", "/usr/bin:/bin")}

DETECTOR_NAMES = (
    "auto_register_receiver", "block_randomness", "callback_ignores_result", "caller_supplied_price",
    "check_without_update", "deduct_after_success", "deploy_without_auth", "div_before_mul", "float_amount",
    "narrowing_cast", "nep_method_without_yocto", "nft_approval_without_owner", "non_private_callback",
    "prepaid_gas_unchecked", "privileged_without_auth", "privileged_without_yocto", "receiver_trusts_caller",
    "reinit_without_auth", "round_direction", "self_transfer", "signer_comparison", "signer_identity", "stale_price",
    "state_growth_unpaid", "unbounded_loop", "unhandled_value_promise", "unregister_ignores_balance",
    "unsaved_changes", "wrapping_math")
DETECTOR_KEYS = tuple(f"det_{d}" for d in DETECTOR_NAMES)

CONTEXT_KEYS = (
    "ctx_cb_scheduled", "ctx_cb_resolved", "ctx_cb_unprivate", "ctx_cb_no_result",
    "ctx_is_cb_target", "ctx_cb_target_unprotected",
    "ctx_owner_field", "ctx_n_auth_helpers", "ctx_calls_auth_helper", "ctx_owner_unchecked_mut_entry",
    "ctx_n_mut_entries", "ctx_entries_auth_rate", "ctx_entries_yocto_rate", "ctx_incons_auth", "ctx_incons_yocto",
    "ctx_n_similar", "ctx_similar_auth_rate", "ctx_similar_yocto_rate", "ctx_similar_private_rate",
    "ctx_incons_similar_auth", "ctx_incons_similar_yocto", "ctx_incons_similar_private",
    "ctx_n_callers", "ctx_n_callers_entry", "ctx_n_callers_entry_noauth",
    "ctx_overflow_checks", "ctx_sdk_version", "ctx_crate_fns", "ctx_crate_lines", "ctx_file_fns",
    "ctx_self_auth", "ctx_self_yocto", "ctx_self_private", "ctx_self_mut_entry")

OWNER_FIELD = re.compile(r"\b\w*(?:owner|admin|operator|guardian|governance|dao|council)\w*\s*:\s*"
                         r"(?:Option\s*<\s*)?(?:near_sdk::)?(?:AccountId|ValidAccountId|String)\b")
SDK_DEP = re.compile(r"^\s*near-sdk\s*=\s*(\"[^\"]*\"|\{[^}\n]*\})", re.M)
NAME_STOP = {"fn", "internal", "the", "to", "of", "for", "and", "by", "from", "with", "in", "on", "is", "get", "new"}
COMMON_NAMES = {"new", "default", "get", "set", "into", "from", "clone", "len", "unwrap", "insert", "remove", "push",
                "contains", "iter", "map", "to_string", "as_ref", "build", "id", "transfer", "deposit", "withdraw"}


def _crate_dirs(keys) -> set[str]:
    return {posixpath.dirname(k) for k in keys if posixpath.basename(k) == "Cargo.toml"}


def _ancestors(path: str) -> list[str]:
    """Directories from the file's own dir up to the root ('')."""
    out, d = [], posixpath.dirname(path)
    while True:
        out.append(d)
        if not d:
            return out
        d = posixpath.dirname(d)


def crate_root(keys, path: str) -> str | None:
    """Nearest ancestor directory of `path` holding a Cargo.toml among `keys`; None when there is none."""
    dirs = _crate_dirs(keys)
    return next((d for d in _ancestors(path) if d in dirs), None)


def scope_paths(keys, path: str, crate: bool = False) -> list[str]:
    """The files that make up the context of a function in `path`, chosen from file names only (see module doc)."""
    keys = list(keys)
    rs = [path] if path in keys else []
    if crate:
        root = crate_root(keys, path)
        prefix = "" if not root else root + "/"
        rs += sorted(k for k in keys if k.endswith(".rs") and k.startswith(prefix) and k != path
                     and not TEST_PATH.search(k) and "/target/" not in f"/{k}")[:MAX_FILES - 1]
    tomls = [posixpath.join(d, "Cargo.toml") if d else "Cargo.toml" for d in _ancestors(path)]
    return rs + [t for t in tomls if t in set(keys)]


def _git(repo_dir: str, *args: str, inp: bytes | None = None) -> bytes | None:
    try:
        p = subprocess.run(["git", "-C", repo_dir, *args], input=inp, capture_output=True, timeout=300, env=GIT_ENV)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout if p.returncode == 0 else None


def git_listing(repo_dir: str, commit: str) -> list[str] | None:
    out = _git(repo_dir, "ls-tree", "-r", "--name-only", "-z", commit)
    return None if out is None else [p for p in out.decode("utf8", "replace").split("\0") if p]


def git_read(repo_dir: str, commit: str, paths: list[str]) -> dict[str, str]:
    """Blob contents at `commit` (offline: blobs missing from a partial clone are skipped)."""
    if not paths:
        return {}
    out = _git(repo_dir, "cat-file", "--batch", inp="".join(f"{commit}:{p}\n" for p in paths).encode())
    if out is None:
        return {}
    files, i = {}, 0
    for p in paths:
        j = out.index(b"\n", i)
        head = out[i:j].split()
        if len(head) == 3 and head[1] == b"blob":
            n = int(head[2])
            if n <= MAX_FILE_BYTES:
                files[p] = out[j + 1:j + 1 + n].decode("utf8", "replace")
            i = j + 1 + n + 1
        else:
            i = j + 1
    return files


def git_files(repo_dir: str, commit: str, path: str, listing: list[str] | None = None) -> dict[str, str] | None:
    """The scope files of `path` at `commit` in a local clone, or None when the function's own file is unavailable."""
    keys = listing if listing is not None else git_listing(repo_dir, commit)
    if not keys or path not in keys:
        return None
    files = git_read(repo_dir, commit, scope_paths(keys, path))
    return files if path in files else None


def _name_tokens(name: str) -> set[str]:
    return {t for t in re.split(r"_+", name.lower()) if t and t not in NAME_STOP}


def _rec(fn: dict, file_src: str | None) -> dict:
    """Per-function flags shared by the crate tables and the function itself."""
    try:
        c = context(fn, file_src)
    except Exception:
        return {"name": fn.get("fn") or "", "ok": False}
    body = c["body"]
    return {"name": c["name"], "impl": fn.get("impl"), "path": fn.get("path"), "ok": True,
            "mut_entry": bool(c["entry"] and c["mut"] and not c["init"]), "entry": bool(c["entry"]),
            "auth": bool(c["auth"]), "private": bool(c["private"]), "yocto": bool(YOCTO.search(body)),
            "result": bool(PROMISE_RESULT.search(body)) or bool(c["attrs"] & CALLBACK_ATTRS),
            "pred_cmp": c["pred_cmp"] is not None, "body": body,
            "tokens": _name_tokens(c["name"])}


def _sdk_version(tomls: list[str]) -> float:
    """near-sdk major + minor / 100 from the nearest Cargo.toml naming a version (`workspace = true` defers to an
    ancestor's [workspace.dependencies]); -1 when unknown (no manifest, git or path dependency)."""
    for t in tomls:
        for m in SDK_DEP.finditer(t):
            spec = m.group(1)
            if spec.startswith("{"):
                vm = re.search(r"version\s*=\s*\"([^\"]*)\"", spec)
                if vm is None:
                    continue
                spec = vm.group(1)
            v = re.search(r"(\d+)(?:\.(\d+))?", spec)
            if v:
                return float(v.group(1)) + float(v.group(2) or 0) / 100.0
    return -1.0


def build_crate(files: dict[str, str], path: str) -> dict:
    """Crate tables for functions in `path`: every non-test function of the scope files with its flags."""
    keys = scope_paths(files.keys(), path)
    rs = [k for k in keys if k.endswith(".rs")]
    tomls = [files[k] for k in keys if k.endswith("Cargo.toml")]
    fns = []
    for k in rs:
        for f in extract_functions(files[k], k):
            if not f.get("is_test"):
                fns.append(_rec(f, files[k]))
    text = "\n".join(files[k] for k in rs)
    stripped = strip_code(text)
    helpers = set()
    for r in fns:
        if r["ok"] and not r["mut_entry"] and (AUTH_COMPARE.search(r["body"]) or (r["pred_cmp"] and (
                re.search(r"\bself\s*\.", r["body"]) or SELF_CHECK.search(r["body"])))):
            helpers.add(r["name"])
    if tomls:
        oc = 1.0 if any(overflow_checks_enabled(t) for t in tomls) else 0.0
    else:
        oc = -1.0
    return {"fns": [r for r in fns if r["ok"]], "cb_targets": callback_names(text) if text else frozenset(),
            "owner_field": bool(OWNER_FIELD.search(stripped)), "helpers": helpers, "overflow": oc,
            "sdk": _sdk_version(tomls), "n_lines": text.count("\n") + 1 if text else 0,
            "file_fns": {k: sum(1 for r in fns if r["path"] == k) for k in rs}}


def _calls(body: str, name: str) -> bool:
    return bool(re.search(rf"(?:\bself\s*\.\s*|\bSelf\s*::\s*|(?<![\w.:]))\b{re.escape(name)}\s*\(", body))


def _rate(xs: list[bool]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def fn_context(fn: dict, path: str, crate: dict, file_src: str | None) -> dict[str, float]:
    """CONTEXT_KEYS for `fn` (a function record with code/fn/impl/attrs/...); crate from build_crate."""
    me = _rec(dict(fn, path=path), file_src)
    out = dict.fromkeys(CONTEXT_KEYS, 0.0)
    out.update(ctx_overflow_checks=crate["overflow"], ctx_sdk_version=crate["sdk"],
               ctx_crate_fns=math.log1p(len(crate["fns"])), ctx_crate_lines=math.log1p(crate["n_lines"]),
               ctx_file_fns=math.log1p(crate["file_fns"].get(path, 0)), ctx_owner_field=float(crate["owner_field"]))
    if not me["ok"]:
        return out
    name = me["name"]
    others = [r for r in crate["fns"] if not (r["name"] == name and r["path"] == path
                                              and (not fn.get("impl") or not r["impl"] or r["impl"] == fn.get("impl")))]
    by_name: dict[str, list[dict]] = {}
    for r in others:
        by_name.setdefault(r["name"], []).append(r)
    body = me["body"]
    out.update(ctx_self_auth=float(me["auth"]), ctx_self_yocto=float(me["yocto"]),
               ctx_self_private=float(me["private"]), ctx_self_mut_entry=float(me["mut_entry"]))

    sched = callback_names(fn.get("code") or "") - {name}
    resolved = [by_name[n] for n in sched if n in by_name]
    out.update(ctx_cb_scheduled=float(len(sched)), ctx_cb_resolved=float(len(resolved)),
               ctx_cb_unprivate=float(sum(any(not r["private"] for r in rs) for rs in resolved)),
               ctx_cb_no_result=float(sum(any(not r["result"] for r in rs) for rs in resolved)))
    target = name in crate["cb_targets"]
    out.update(ctx_is_cb_target=float(target),
               ctx_cb_target_unprotected=float(target and me["entry"] and not me["private"]))

    helpers = crate["helpers"] - {name}
    calls_helper = any(_calls(body, h) for h in helpers)
    out.update(ctx_n_auth_helpers=float(len(helpers)), ctx_calls_auth_helper=float(calls_helper),
               ctx_owner_unchecked_mut_entry=float(bool(me["mut_entry"] and (helpers or crate["owner_field"])
                                                        and not calls_helper and not me["auth"])))

    entries = [r for r in others if r["mut_entry"] and r["name"] != name]
    a_rate, y_rate = _rate([r["auth"] for r in entries]), _rate([r["yocto"] for r in entries])
    out.update(ctx_n_mut_entries=math.log1p(len(entries)), ctx_entries_auth_rate=a_rate, ctx_entries_yocto_rate=y_rate)
    if me["mut_entry"]:
        out.update(ctx_incons_auth=a_rate * (not (me["auth"] or calls_helper)), ctx_incons_yocto=y_rate * (not me["yocto"]))
    sim = [r for r in entries if me["tokens"] and len(me["tokens"] & r["tokens"]) / len(me["tokens"] | r["tokens"]) >= 0.3]
    sa, sy, sp_ = (_rate([r[k] for r in sim]) for k in ("auth", "yocto", "private"))
    out.update(ctx_n_similar=math.log1p(len(sim)), ctx_similar_auth_rate=sa, ctx_similar_yocto_rate=sy,
               ctx_similar_private_rate=sp_)
    if me["mut_entry"] or target:
        out.update(ctx_incons_similar_auth=sa * (not (me["auth"] or calls_helper)),
                   ctx_incons_similar_yocto=sy * (not me["yocto"]), ctx_incons_similar_private=sp_ * (not me["private"]))

    if len(name) >= 4 and name not in COMMON_NAMES:
        callers = [r for r in others if r["name"] != name and _calls(r["body"], name)]
        out.update(ctx_n_callers=math.log1p(len(callers)),
                   ctx_n_callers_entry=math.log1p(sum(r["entry"] for r in callers)),
                   ctx_n_callers_entry_noauth=math.log1p(sum(r["mut_entry"] and not r["auth"] for r in callers)))
    return out


def detector_counts(fn: dict, file_src: str | None) -> dict[str, float]:
    out = dict.fromkeys(DETECTOR_KEYS, 0.0)
    for h in detect(fn, file_src):
        k = f"det_{h['detector']}"
        if k in out:
            out[k] += 1.0
    return out


def fn_record(r: dict) -> dict:
    return {k: r.get(k) for k in ("code", "fn", "impl", "attrs", "is_near_bindgen", "is_public", "trait",
                                  "is_payable", "start_line")}


def row_context(fn: dict, path: str, files: dict[str, str] | None, crate_cache: dict | None = None) -> dict:
    """{context: CONTEXT_KEYS dict, detectors: DETECTOR_KEYS dict, file_src, available}. files None or without
    `path` -> the function alone. crate_cache (scope paths -> crate tables) must belong to this one `files` dict."""
    available = bool(files) and path in files
    if not available:
        files = {path: fn.get("code") or ""}
    ck = tuple(scope_paths(files.keys(), path))
    if crate_cache is not None and available and ck in crate_cache:
        crate = crate_cache[ck]
    else:
        crate = build_crate(files, path)
        if crate_cache is not None and available:
            crate_cache[ck] = crate
    src = files[path]
    return {"context": fn_context(fn, path, crate, src), "detectors": detector_counts(fn, src), "file_src": src,
            "available": available}


def source_context(files: dict[str, str], fns: list[dict]) -> list[dict]:
    """Inference: row_context for each extracted function (records carry `path`) over the full `files` dict."""
    cache: dict = {}
    return [row_context(f, f.get("path") or "", files, cache) for f in fns]
