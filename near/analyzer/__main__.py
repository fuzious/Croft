"""`python -m near.analyzer PATH [--all] [--stats]`: JSON line per function with detector hits (--all: every function).
--stats prints one JSON summary instead: functions scanned and hits per detector."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .detectors import detect
from .rust_parse import extract_functions

SKIP_DIRS = {"target", ".git", "node_modules", "vendor"}


def rust_files(root: Path):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*.rs")):
        if not SKIP_DIRS & set(p.relative_to(root).parts[:-1]) and p.is_file():
            yield p


def scan(root: Path):
    """Yield (path, fn, hits) for every function under root."""
    for p in rust_files(root):
        try:
            src = p.read_text(encoding="utf8", errors="replace")
        except OSError:
            continue
        for fn in extract_functions(src, str(p)):
            yield p, fn, detect(fn, src)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m near.analyzer")
    ap.add_argument("path", type=Path)
    ap.add_argument("--all", action="store_true", help="print functions without hits too")
    ap.add_argument("--stats", action="store_true", help="print a hit-rate summary instead of functions")
    a = ap.parse_args(argv)
    n_fns, n_entry, n_hit_fns, per_det = 0, 0, 0, Counter()
    for p, fn, hits in scan(a.path):
        n_fns += 1
        n_entry += bool(fn["is_near_bindgen"] and fn["is_public"])
        n_hit_fns += bool(hits)
        per_det.update(f"{h['vuln_class']}/{h['detector']}" for h in hits)
        if not a.stats and (hits or a.all):
            row = {k: fn[k] for k in ("path", "fn", "impl", "trait", "is_near_bindgen", "attrs", "start_line",
                                      "end_line", "is_public", "is_payable")}
            print(json.dumps({**row, "hits": hits}))
    if a.stats:
        print(json.dumps({"path": str(a.path), "functions": n_fns, "near_bindgen_public": n_entry,
                          "functions_with_hits": n_hit_fns, "hits": dict(per_det.most_common())}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
