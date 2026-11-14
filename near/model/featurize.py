"""Row -> model inputs: analyzer features (signed log), hashed code-token 1-3 grams and char 3-5 grams.

All features come from the function text plus its extraction fields (attrs, is_near_bindgen, is_public, trait);
no file context is passed to the analyzer, so every source (audit, fix commit, corpus, mutation) is featurized the
same way. Real rows lack trait/is_public/is_payable: `fill_context` restores them by re-extracting the function from
the local clone (offline, `git show commit:path`), else derives them from the code's own `pub` visibility.
"""
from __future__ import annotations

import os
import re
import subprocess
from functools import lru_cache
from multiprocessing import Pool

import numpy as np
import scipy.sparse as sp
from sklearn.feature_extraction.text import HashingVectorizer

from near.analyzer import extract_functions, features
from near.analyzer.features import FEATURE_KEYS

REPOS_DIR = "near/data/raw/repos"
TOKEN_DIM = 2 ** 20
CHAR_DIM = 2 ** 20
_LIT = re.compile(r'//[^\n]*|/\*.*?\*/|r(#*)".*?"\1|b?"(?:\\.|[^"\\])*"|b?\'(?:\\.|[^\\\'\n])\'', re.S)
_TOK = re.compile(r"\d[\d_]*(?:\.\d+)?\w*|[A-Za-z_]\w*|::|->|=>|==|!=|<=|>=|&&|\|\||[+\-*/%]=|[-+*/%<>!?&|=#@^~]")
_PUB = re.compile(r"^\s*pub\s+(?:(?:const|async|unsafe|extern\s+\"\w+\")\s+)*fn\b", re.M)


def _literals(code: str) -> str:
    """Comments -> space, string/char literals -> S."""
    return _LIT.sub(lambda m: " " if m.group(0).startswith(("//", "/*")) else " S ", code)


def code_tokens(code: str) -> list[str]:
    return ["0" if t[0].isdigit() else t for t in _TOK.findall(_literals(code))]


def char_text(code: str) -> str:
    return " ".join(_literals(code).split())


def meta_tokens(r: dict) -> list[str]:
    out = [f"ATTR_{a}" for a in r.get("attrs") or []]
    for key, tok in (("is_near_bindgen", "BINDGEN"), ("is_public", "PUBLIC"), ("trait", "TRAIT"),
                     ("is_payable", "PAYABLE")):
        if r.get(key):
            out.append(tok)
    return out


def token_ngrams(r: dict) -> list[str]:
    t = code_tokens(r["code"])
    grams = t + [f"{a} {b}" for a, b in zip(t, t[1:])] + [f"{a} {b} {c}" for a, b, c in zip(t, t[1:], t[2:])]
    return grams + meta_tokens(r)


def _ident(x):
    return x


TOKEN_HASH = HashingVectorizer(analyzer=_ident, n_features=TOKEN_DIM, alternate_sign=False, binary=True, norm="l2")
CHAR_HASH = HashingVectorizer(analyzer="char", ngram_range=(3, 5), n_features=CHAR_DIM, alternate_sign=False,
                              binary=True, norm="l2", lowercase=False)


@lru_cache(maxsize=4096)
def _file_fns(repo_dir: str, commit: str, path: str) -> tuple:
    env = {"GIT_NO_LAZY_FETCH": "1", "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    try:
        p = subprocess.run(["git", "-C", repo_dir, "show", f"{commit}:{path}"], capture_output=True, text=True,
                           timeout=60, env=env)
    except (OSError, subprocess.SubprocessError):
        return ()
    return tuple(extract_functions(p.stdout, path)) if p.returncode == 0 else ()


def _squash(s: str) -> str:
    return "".join(s.split())


def fill_context(rows: list[dict], repos_dir: str = REPOS_DIR) -> None:
    """Set trait/is_public/is_payable in place where missing; `context_from` = row | repo | code."""
    for r in rows:
        if "is_public" in r and "trait" in r:
            r["context_from"] = "row"
            continue
        hit = None
        if r.get("fetched_from") and r.get("commit") and r.get("path") and not r.get("code_from_snippet"):
            d = os.path.join(repos_dir, r["fetched_from"])
            if os.path.isdir(d):
                want = _squash(r["code"])
                hit = next((f for f in _file_fns(d, r["commit"], r["path"]) if _squash(f["code"]) == want), None)
        if hit is not None:
            r.update(trait=hit["trait"], is_public=hit["is_public"], is_payable=hit["is_payable"], context_from="repo")
        else:
            r.update(trait=None, is_public=bool(_PUB.search(_literals(r["code"]))),
                     is_payable="payable" in (r.get("attrs") or []), context_from="code")


def _fn_record(r: dict) -> dict:
    return {k: r.get(k) for k in ("code", "fn", "impl", "attrs", "is_near_bindgen", "is_public", "trait",
                                  "is_payable")}


def _feat_row(r: dict) -> list[float]:
    f = features(_fn_record(r))
    return [f[k] for k in FEATURE_KEYS]


def _pmap(fn, items, workers: int, chunk: int = 256):
    if workers <= 1:
        return list(map(fn, items))
    with Pool(workers) as p:
        return p.map(fn, items, chunksize=chunk)


def analyzer_matrix(rows: list[dict], workers: int = 16) -> np.ndarray:
    """Analyzer features in FEATURE_KEYS order, signed-log scaled: sign(x) * log1p(|x|)."""
    X = np.array(_pmap(_feat_row, [_fn_record(r) for r in rows], workers), dtype=np.float64).reshape(-1, len(FEATURE_KEYS))
    return np.sign(X) * np.log1p(np.abs(X))


def _tok_chunk(chunk):
    return TOKEN_HASH.transform([token_ngrams(r) for r in chunk]).astype(np.float32)


def _char_chunk(chunk):
    return CHAR_HASH.transform([char_text(r["code"]) for r in chunk]).astype(np.float32)


def text_matrices(rows: list[dict], workers: int = 16, chunk: int = 1000):
    """(token 1-3 gram hashes + meta tokens, char 3-5 gram hashes), each row l2-normalized, CSR float32."""
    slim = [{k: r.get(k) for k in ("code", "attrs", "is_near_bindgen", "is_public", "trait", "is_payable")}
            for r in rows]
    chunks = [slim[i:i + chunk] for i in range(0, len(slim), chunk)]
    T = sp.vstack(_pmap(_tok_chunk, chunks, workers, 1)).tocsr()
    C = sp.vstack(_pmap(_char_chunk, chunks, workers, 1)).tocsr()
    return T, C
