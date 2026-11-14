"""Vulnerability injection: remove one protection from a safe NEAR contract function, one operator per vuln_class.

    uv run python -m near.collect.mutate      # -> near/data/mutation_samples.jsonl, near/data/mutation_report.md

Source functions come from clones of repos with stars >= 3 or audited (cloned code is only parsed, never built).
Each kept function is emitted once as label 0 (source mutation_original) and with up to 2 mutants as label 1
(source mutation, field operator); pair_id of every row is the id of the original. A mutant is kept only when it
parses with tree-sitter without errors and differs from the original after normalization.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import random
import re
import sys
from multiprocessing import Pool
from pathlib import Path

from near.analyzer import extract_functions
from near.analyzer.detectors import (AUTH_ATTR, AUTH_COMPARE, AUTH_HELPER, AMOUNT, CALLBACK_ATTRS, CALLBACK_NAME,
                                     DEPLOY, EXT_CALL, PREDECESSOR, PROMISE_RESULT, RECEIVERS, SELF_CHECK,
                                     THEN, VALUE_CALL, YOCTO, strip_code, strip_comments)
from near.analyzer.rust_parse import PARSER
from near.collect.corpus import REPOS_JSONL, SKIP_DIRS

OUT = Path("near/data/mutation_samples.jsonl")
REPORT = Path("near/data/mutation_report.md")
PER_OP, PER_FN = 30, 2


# ---------- tree / text helpers (byte offsets everywhere; latin-1 keeps stripped text aligned with bytes) ----------

def _tree(code: str):
    b = code.encode("utf8")
    return b, PARSER.parse(b).root_node


def _walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _t(b: bytes, n) -> str:
    return b[n.start_byte:n.end_byte].decode("utf8", errors="replace")


def _s(b: bytes, n=None) -> str:
    """Comment- and string-blanked text of a node (or all of b), one char per byte."""
    return strip_code((b if n is None else b[n.start_byte:n.end_byte]).decode("latin-1"))


def clean_parse(code: str) -> bool:
    """True when tree-sitter parses the code without ERROR or MISSING nodes."""
    return not PARSER.parse(code.encode("utf8")).root_node.has_error


def normalized(code: str) -> str:
    return re.sub(r"\s+", "", strip_comments(code))


def _apply(b: bytes, edits: list) -> str:
    """Apply (start, end, replacement) edits; overlapping deletions merge, other overlaps keep the first."""
    out = []
    for s, e, r in sorted(edits, key=lambda x: (x[0], x[1])):
        if out and s < out[-1][1]:
            if r == b"" and out[-1][2] == b"":
                out[-1] = (out[-1][0], max(e, out[-1][1]), b"")
            continue
        out.append((s, e, r))
    for s, e, r in reversed(out):
        b = b[:s] + r + b[e:]
    return b.decode("utf8", errors="replace")


def _line_bounds(b: bytes, i: int) -> tuple[int, int]:
    s = b.rfind(b"\n", 0, i) + 1
    e = b.find(b"\n", i)
    return s, (len(b) if e < 0 else e)


def _del(b: bytes, n) -> tuple:
    """Deletion edit for a node: whole lines (plus attached `//` comments, tidy blank lines) when it owns them."""
    s, e = n.start_byte, n.end_byte
    ls, _ = _line_bounds(b, s)
    _, le = _line_bounds(b, e)
    tail = b[e:le].strip()
    if b[ls:s].strip() or (tail and not tail.startswith(b"//")):
        while e < len(b) and b[e:e + 1] == b" ":
            e += 1
        return s, e, b""
    le = min(le + 1, len(b))
    while ls > 0:
        pls, _ = _line_bounds(b, ls - 1)
        prev = b[pls:ls].strip()
        if prev.startswith(b"//") and not prev.startswith((b"///", b"//!")):
            ls = pls
        else:
            break
    prev_line = b[_line_bounds(b, ls - 1)[0]:ls].strip() if ls > 0 else b""
    nls, nle = _line_bounds(b, le) if le < len(b) else (le, le)
    next_line = b[nls:nle].strip()
    if le < len(b) and not next_line and (not prev_line or prev_line.endswith(b"{")):
        le = min(nle + 1, len(b))
    elif next_line.startswith(b"}") and not prev_line and ls > 0:
        ls = _line_bounds(b, ls - 1)[0]
    return ls, le, b""


def _fn_node(root):
    return next((c for c in root.children if c.type == "function_item"), None)


def _attr_items(root) -> list:
    return [c for c in root.children if c.type == "attribute_item"]


def _method(b: bytes, call):
    """(method name, receiver node, arguments node) of `recv.method(args)`, else None."""
    if call.type != "call_expression":
        return None
    fn = call.child_by_field_name("function")
    if fn is None or fn.type != "field_expression":
        return None
    return _t(b, fn.child_by_field_name("field")), fn.child_by_field_name("value"), call.child_by_field_name("arguments")


def _args(node) -> list:
    return [c for c in node.named_children if c.type not in ("line_comment", "block_comment")] if node else []


def _wrap(b: bytes, n) -> str:
    t = _t(b, n)
    return f"({t})" if n.type in ("binary_expression", "range_expression", "closure_expression") else t


SAFE_PARENTS = {"let_declaration", "assignment_expression", "compound_assignment_expr", "arguments",
                "expression_statement", "return_expression", "block", "match_arm", "field_initializer",
                "parenthesized_expression", "array_expression", "tuple_expression"}


def _maybe_paren(n, text: str) -> str:
    return text if n.parent is None or n.parent.type in SAFE_PARENTS else f"({text})"


# ---------- guard statements ----------

GUARD_CALL = re.compile(r"^(?:assert|require|ensure|only|check|verify|validate|internal_assert|internal_check"
                        r"|abort_if|panic_if)_\w*$|^\w+_only$|^only\w*$")
GUARD_MACROS = {"assert", "assert_eq", "assert_ne", "require"}
PANICKY = re.compile(r"panic|abort|\breturn\b|\bErr\s*\(|unreachable!|require!\s*\(\s*false|throw")
SIDE_EFFECT = re.compile(r"\.\s*(?:insert|remove|push|pop|set|replace|take|clear|extend|append|drain|swap_remove)\s*\("
                         r"|Promise::|\bext_\w*::|::\s*ext\s*\(|\binternal_(?!get|view|is|check|assert)\w+\s*\(")


def _check_text(b: bytes, n) -> str | None:
    """Stripped text of a guard statement (assert!/require!, assert_*/check_* call, `if c { panic/return }`), else None.
    A guard whose condition has side effects (`assert!(map.insert(..).is_none())`) is not deletable and yields None."""
    if n.type != "expression_statement" or not n.named_children:
        return None
    c = n.named_children[0]
    cond = c.child_by_field_name("condition") if c.type == "if_expression" else c
    if cond is None or SIDE_EFFECT.search(_s(b, cond)):
        return None
    c = n.named_children[0]
    if c.type == "macro_invocation":
        name = _t(b, c.child_by_field_name("macro")).split("::")[-1]
        return _s(b, n) if name in GUARD_MACROS else None
    if c.type == "call_expression":
        name = re.split(r"\.|::", _t(b, c.child_by_field_name("function")))[-1].strip()
        return _s(b, n) if GUARD_CALL.match(name) else None
    if c.type == "if_expression" and c.child_by_field_name("alternative") is None:
        cons = c.child_by_field_name("consequence")
        body = _s(b, cons) if cons is not None else ""
        if PANICKY.search(body) and len(body) < 500:
            return _s(b, n)
    return None


def _checks(b: bytes, root) -> list:
    out = []
    for n in _walk(root):
        txt = _check_text(b, n)
        if txt is not None:
            out.append((n, txt))
    return out


IMPURE = re.compile(r"\.\s*(?:insert|remove|push|pop|set|replace|take|clear|extend|append|drain)\s*\(|Promise"
                    r"|\bext_|::\s*ext\s*\(|internal_\w+\s*\(|!\s*\(|\bself\.\w+\s*\(")


def _let_names(b: bytes, root) -> list:
    out = []
    for n in _walk(root):
        if n.type == "let_declaration":
            pat, val = n.child_by_field_name("pattern"), n.child_by_field_name("value")
            if pat is not None and pat.type == "identifier" and val is not None:
                out.append((n, _t(b, pat), val))
    return out


def _dead(b: bytes, root) -> set:
    s = _s(b)
    return {name for n, name, _ in _let_names(b, root)
            if not re.search(rf"\b{re.escape(name)}\b", s[:n.start_byte] + s[n.end_byte:])}


def _drop_dead_lets(code: str, original: str) -> str:
    """Delete `let x = <pure expr>;` whose x became unused after a mutation (repeat to a fixpoint)."""
    ob, oroot = _tree(original)
    keep = _dead(ob, oroot)
    for _ in range(5):
        b, root = _tree(code)
        s = _s(b)
        edits = []
        for n, name, val in _let_names(b, root):
            if name in keep or IMPURE.search(_s(b, val)):
                continue
            if not re.search(rf"\b{re.escape(name)}\b", s[:n.start_byte] + s[n.end_byte:]):
                edits.append(_del(b, n))
        if not edits:
            return code
        code = _apply(b, edits)
    return code


def _delete_checks(f: dict, pred, attr_pred=None, cleanup: bool = True) -> str | None:
    """Delete every guard statement whose stripped text satisfies pred (and attributes satisfying attr_pred).
    Guard helpers themselves (assert_owner, check_registered, ...) are left alone: emptying them looks synthetic."""
    if HELPER_NAME.match(f["fn"]):
        return None
    b, root = _tree(f["code"])
    edits = [_del(b, n) for n, txt in _checks(b, root) if pred(txt)]
    if attr_pred:
        edits += [_del(b, a) for a in _attr_items(root) if attr_pred(_t(b, a))]
    if not edits:
        return None
    out = _apply(b, edits)
    return _drop_dead_lets(out, f["code"]) if cleanup else out


# ---------- function classification ----------

UPGRADE_NAME = re.compile(r"^(?:migrate\w*|upgrade\w*|update_contract|update_code|set_code|stage_code|deploy_code"
                          r"|deploy_contract|self_upgrade)$")
HELPER_NAME = re.compile(r"^(?:assert|require|check|only|ensure|is|verify|validate|internal_assert|internal_check)_")
PRIVATE_ATTR = re.compile(r"^#\[\s*private\s*\]$")


def _is_callback(f: dict) -> bool:
    return bool(CALLBACK_NAME.search(f["fn"]) or CALLBACK_ATTRS & set(f["attrs"]) or PROMISE_RESULT.search(f["code"]))


def _is_upgrade(f: dict) -> bool:
    return bool(UPGRADE_NAME.match(f["fn"]) or (DEPLOY.search(f["code"]) and "current_account_id" in f["code"]))


OWNERISH = re.compile(r"\bself\.(?:\w+\.)*\w*(?:owner|admin|operator|guardian|governance|dao|council|manager|role"
                      r"|whitelist|allowlist)\w*", re.I)
CALLER = re.compile(r"predecessor_account_id|\bcaller\b|\bsender\w*|\bsigner\w*|\baccount_id\b")


def _is_auth(txt: str) -> bool:
    if SELF_CHECK.search(txt):
        return False
    return bool(AUTH_HELPER.search(txt) or AUTH_COMPARE.search(txt) or (OWNERISH.search(txt) and CALLER.search(txt)))


# ---------- operators: fn dict -> mutated code or None ----------

def op_non_private_callback(f: dict) -> str | None:
    if "init" in f["attrs"] or _is_upgrade(f) or not _is_callback(f):
        return None
    return _delete_checks(f, lambda t: bool(SELF_CHECK.search(t)), lambda a: bool(PRIVATE_ATTR.match(a)))


RESTORE = re.compile(r"self\.|Promise::new|\.insert\s*\(|\+=|-=|refund|transfer|internal_\w+\s*\(|rollback|revert"
                     r"|restore|\bext_|::\s*ext\s*\(")
FAIL_PAT = re.compile(r"Failed|NotReady|\bErr\b|^_$|\bNone\b")
CB_PARAM = re.compile(r"#\[\s*callback_result\s*\]\s*(?:mut\s+)?(\w+)\s*:")


def _gut(b: bytes, block) -> tuple[list, bool]:
    """Edits deleting the statements of a block (keeping a tail expression); True when nothing is left."""
    stmts = [c for c in block.named_children if c.type in ("expression_statement", "let_declaration")]
    rest = [c for c in block.named_children if c not in stmts and c.type not in ("line_comment", "block_comment")]
    if not rest:
        return [(block.start_byte, block.end_byte, b"{}")], True
    return [_del(b, c) for c in stmts], False


def op_unhandled_promise_result(f: dict) -> str | None:
    code = f["code"]
    if not PROMISE_RESULT.search(code) and "callback_result" not in f["attrs"]:
        return None
    b, root = _tree(code)
    params = set(CB_PARAM.findall(code))
    flags = {name for _, name, val in _let_names(b, root) if PROMISE_RESULT.search(_s(b, val))}
    mentions = lambda t, names: any(re.search(rf"\b{re.escape(x)}\b", t) for x in names)
    is_result = lambda t: bool(PROMISE_RESULT.search(t)) or mentions(t, params | flags)
    edits = [_del(b, n) for n, txt in _checks(b, root) if PROMISE_RESULT.search(txt)]
    for n in _walk(root):
        if n.type == "match_expression" and is_result(_s(b, n.child_by_field_name("value"))):
            for arm in (c for c in n.child_by_field_name("body").named_children if c.type == "match_arm"):
                pat, val = arm.child_by_field_name("pattern"), arm.child_by_field_name("value")
                if pat is None or val is None or not FAIL_PAT.search(_t(b, pat).strip()) or not RESTORE.search(_s(b, val)):
                    continue
                edits += _gut(b, val)[0] if val.type == "block" else [(val.start_byte, val.end_byte, b"{}")]
        elif n.type == "if_expression":
            cond = n.child_by_field_name("condition")
            ctext = _s(b, cond) if cond is not None else ""
            if not (PROMISE_RESULT.search(ctext) or mentions(ctext, flags)
                    or mentions(ctext, params) and re.search(r"is_err|is_ok|Err|Ok", ctext)):
                continue
            cons, alt = n.child_by_field_name("consequence"), n.child_by_field_name("alternative")
            negated = bool(re.search(r"^\s*!|is_err|Err\s*\(|Failed|NotReady", ctext))
            if negated and alt is None and RESTORE.search(_s(b, cons)):
                edits += [_del(b, n.parent)] if n.parent.type == "expression_statement" else _gut(b, cons)[0]
            elif not negated and alt is not None:
                blk = next((c for c in alt.named_children if c.type == "block"), None)
                if blk is None or not RESTORE.search(_s(b, blk)):
                    continue
                gut, empty = _gut(b, blk)
                edits += [(cons.end_byte, alt.end_byte, b"")] if empty else gut
            elif negated and alt is not None and RESTORE.search(_s(b, cons)):
                gut, empty = _gut(b, cons)
                blk = next((c for c in alt.named_children if c.type == "block"), None)
                if empty and blk is not None and ctext.lstrip().startswith("!"):  # `if !ok {} else {A}` -> `if ok {A}`
                    edits.append((n.start_byte, n.end_byte, f"if {_t(b, cond).lstrip()[1:].lstrip()} {_t(b, blk)}".encode()))
                else:
                    edits += gut
    return _apply(b, edits) if edits else None


DEDUCT = re.compile(r"\bself\.(?:\w+\.)*(?:internal_)?\w*(?:withdraw|sub|decrease|burn|debit|lock|deduct)\w*\s*\("
                    r"|\b\w+(?:\.\w+|\[[^\]]*\])+\s*-=|\bself\.[\w.\[\]]+\s*=[^=][^;]*(?:checked_sub|saturating_sub|\s-\s)")


def op_async_reentrancy(f: dict) -> str | None:
    code = f["code"]
    if _is_callback(f) or "private" in f["attrs"] or not THEN.search(code):
        return None
    b, root = _tree(code)
    s = _s(b)
    calls = [m.start() for rx in (EXT_CALL, VALUE_CALL) for m in rx.finditer(s)]
    if not calls:
        return None
    first = min(calls)
    edits = []
    for n in _walk(root):
        if n.type == "expression_statement" and n.end_byte <= first and _check_text(b, n) is None:
            txt = _s(b, n)
            if DEDUCT.search(txt) and "{" not in txt:
                edits.append(_del(b, n))
    return _apply(b, edits) if edits else None


def _predecessor_names(f: dict) -> list:
    b, root = _tree(f["code"])
    return [name for _, name, val in _let_names(b, root) if PREDECESSOR.search(_s(b, val))]


def op_missing_access_control(f: dict) -> str | None:
    if HELPER_NAME.match(f["fn"]) or f["fn"] in RECEIVERS or _is_upgrade(f):
        return None
    allow_private = not _is_callback(f) and "init" not in f["attrs"]
    caller = re.compile(r"predecessor_account_id" + "".join(rf"|\b{re.escape(x)}\b" for x in _predecessor_names(f)))
    owner_check = lambda t: (bool(re.search(r"assert_(?:eq|ne)!|==|!=", t)) and bool(caller.search(t))
                             and not SELF_CHECK.search(t) and not re.search(r"receiver|recipient", t))
    return _delete_checks(f, lambda t: _is_auth(t) or owner_check(t),
                          lambda a: bool(AUTH_ATTR.search(a) or allow_private and PRIVATE_ATTR.match(a)))


def op_missing_one_yocto(f: dict) -> str | None:
    if not YOCTO.search(f["code"]):
        return None
    return _delete_checks(f, lambda t: bool(YOCTO.search(t)))


def _swap_predecessor(b: bytes, n) -> tuple | None:
    m = re.search(r"\bpredecessor_account_id\b", _s(b, n))
    if not m:
        return None
    return n.start_byte + m.start(), n.start_byte + m.end(), b"signer_account_id"


def op_signer_auth(f: dict) -> str | None:
    if not PREDECESSOR.search(f["code"]):
        return None
    b, root = _tree(f["code"])
    checks = [(n, t) for n, t in _checks(b, root) if not SELF_CHECK.search(t)]
    edits = [e for e in (_swap_predecessor(b, n) for n, t in checks if PREDECESSOR.search(t)) if e]
    if not edits:
        for n, name, val in _let_names(b, root):
            if PREDECESSOR.search(_s(b, val)) and any(re.search(rf"\b{re.escape(name)}\b", t) for _, t in checks):
                edits.append(_swap_predecessor(b, val))
                break
    fn = _fn_node(root)
    if not edits and fn is not None and f["is_public"] and not _is_callback(f) and f["fn"] not in RECEIVERS \
            and "&mut self" in _t(b, fn.child_by_field_name("parameters")) and not SELF_CHECK.search(_s(b)):
        stmts = (n for n in _walk(fn.child_by_field_name("body"))  # caller identity taken from the signer
                 if n.type in ("let_declaration", "expression_statement")
                 and not (n.named_children and n.named_children[0].type == "macro_invocation")
                 and not any(c.type == "block" for c in n.named_children[:1]))
        edits.append(next((e for e in (_swap_predecessor(b, n) for n in stmts) if e), None))
    return _apply(b, [e for e in edits if e]) if any(edits) else None


def op_unguarded_upgrade(f: dict) -> str | None:
    if not _is_upgrade(f):
        return None
    return _delete_checks(f, lambda t: _is_auth(t) or bool(SELF_CHECK.search(t)),
                          lambda a: bool(AUTH_ATTR.search(a) or PRIVATE_ATTR.match(a)))


ARITH = {"checked_add": "+", "checked_sub": "-", "checked_mul": "*",
         "saturating_add": "+", "saturating_sub": "-", "saturating_mul": "*"}
UNWRAPS = {"unwrap", "expect", "unwrap_or_else"}


def _first_amount(b: bytes, cands: list):
    """First candidate whose expression mentions an amount-like name (the spec mutates amount math only)."""
    return next((c for c in cands if AMOUNT.search(_t(b, c[0]))), None)


def op_unsafe_arithmetic(f: dict) -> str | None:
    code = f["code"]
    if not re.search(r"checked_(?:add|sub|mul)|saturating_(?:add|sub|mul)|as u128|U256::from", code):
        return None
    b, root = _tree(code)
    checked, saturating, widening = [], [], []
    for n in _walk(root):
        m = _method(b, n)
        if m and m[0] in UNWRAPS and n.parent is not None:
            inner = _method(b, m[1])
            if inner and inner[0].startswith("checked_") and inner[0] in ARITH and len(_args(inner[2])) == 1:
                checked.append((n, inner))
        elif m and m[0] in ("ok_or", "ok_or_else") and n.parent is not None and n.parent.type == "try_expression":
            inner = _method(b, m[1])
            if inner and inner[0].startswith("checked_") and inner[0] in ARITH and len(_args(inner[2])) == 1:
                checked.append((n.parent, inner))
        if m and m[0].startswith("saturating_") and m[0] in ARITH and len(_args(m[2])) == 1:
            saturating.append((n, m))
        if n.type == "binary_expression" and n.child_by_field_name("operator").type == "*":
            l, r = n.child_by_field_name("left"), n.child_by_field_name("right")
            if all(x.type == "type_cast_expression" and _t(b, x.child_by_field_name("type")) == "u128" for x in (l, r)):
                widening.append((n, None))
    pick = _first_amount(b, checked) or _first_amount(b, saturating)
    if pick:
        node, (name, recv, args) = pick
        text = f"{_wrap(b, recv)} {ARITH[name]} {_wrap(b, _args(args)[0])}"
        return _apply(b, [(node.start_byte, node.end_byte, _maybe_paren(node, text).encode())])
    if widening:
        node = widening[0][0]
        vals = [node.child_by_field_name(k).child_by_field_name("value") for k in ("left", "right")]
        return _apply(b, [(node.start_byte, node.end_byte, f"{_wrap(b, vals[0])} * {_wrap(b, vals[1])}".encode())])
    return None


CEIL_FN = {"ceil_div", "div_ceil", "div_round_up", "round_up_div", "ceil_division", "div_up"}
ROUND_UP = re.compile(r"^(\w*Round\w*)::(Up|Ceil|Ceiling)$")


def _strip_unwraps(b: bytes, n):
    while True:
        if n.type == "try_expression":
            n = n.named_children[0]
            continue
        m = _method(b, n)
        if m and m[0] in UNWRAPS | {"unwrap_or_default", "unwrap_or", "ok_or", "ok_or_else"}:
            n = m[1]
            continue
        return n


def op_precision_rounding(f: dict) -> str | None:
    code = f["code"]
    if "/" not in code and not re.search(r"div|Round", code):
        return None
    b, root = _tree(code)
    ceil, chain, reorder = [], [], []
    for n in _walk(root):
        m = _method(b, n)
        if m and m[0] == "div_ceil" and len(_args(m[2])) == 1:
            ceil.append((n.start_byte, n.end_byte, _maybe_paren(n, f"{_wrap(b, m[1])} / {_wrap(b, _args(m[2])[0])}")))
        elif n.type == "call_expression" and _t(b, n.child_by_field_name("function")).split("::")[-1] in CEIL_FN:
            a = _args(n.child_by_field_name("arguments"))
            if len(a) == 2:
                ceil.append((n.start_byte, n.end_byte, _maybe_paren(n, f"{_wrap(b, a[0])} / {_wrap(b, a[1])}")))
        elif n.type == "scoped_identifier" and ROUND_UP.match(_t(b, n)):
            mm = ROUND_UP.match(_t(b, n))
            ceil.append((n.start_byte, n.end_byte, f"{mm.group(1)}::{'Down' if mm.group(2) == 'Up' else 'Floor'}"))
        elif m and m[0] == "checked_div" and len(_args(m[2])) == 1:
            inner = _method(b, _strip_unwraps(b, m[1]))
            if inner and inner[0] == "checked_mul" and len(_args(inner[2])) == 1:
                dot = lambda call: next(c for c in call.child_by_field_name("function").children if c.type == ".")
                mul_f, div_f = dot(_strip_unwraps(b, m[1])).start_byte, dot(n).start_byte  # `.checked_mul(B)`, `.checked_div(C)`
                mul_s, div_s = _t(b, inner[2]), _t(b, m[2])
                chain.append([(mul_f, inner[2].end_byte, f".checked_div{div_s}"),
                              (div_f, m[2].end_byte, f".checked_mul{mul_s}")])
        elif n.type == "binary_expression" and n.child_by_field_name("operator").type == "/":
            left, c = n.child_by_field_name("left"), n.child_by_field_name("right")
            inner = left.named_children[0] if left.type == "parenthesized_expression" and left.named_children else left
            if inner.type != "binary_expression":
                continue
            op = inner.child_by_field_name("operator").type
            il, ir = inner.child_by_field_name("left"), inner.child_by_field_name("right")
            if op == "-" and _t(b, ir).strip() == "1" and il.type == "binary_expression" \
                    and il.child_by_field_name("operator").type == "+" \
                    and _t(b, il.child_by_field_name("right")) == _t(b, c):
                ceil.append((n.start_byte, n.end_byte, f"({_t(b, il.child_by_field_name('left'))}) / {_t(b, c)}"))
            elif op == "*" and AMOUNT.search(_t(b, n)) and not all(x.type == "integer_literal" for x in (il, ir, c)):
                a = f"({_t(b, il)})" if il.type == "binary_expression" and il.child_by_field_name("operator").type in "+-" \
                    else _t(b, il)
                reorder.append((n.start_byte, n.end_byte, f"{a} / {_wrap(b, c)} * {_wrap(b, ir)}"))
    edits = [ceil[0]] if ceil else chain[0] if chain else [reorder[0]] if reorder else None
    return _apply(b, [(s, e, r.encode()) for s, e, r in edits]) if edits else None


STORAGE_CALL = re.compile(r"\b(?:refund|charge|assert|check|require|ensure|verify|internal_check|internal_assert)_?\w*"
                          r"storage\w*\s*\(|\brefund_(?:deposit|extra)\w*\s*\(", re.I)
STORAGE_TERM = re.compile(r"storage_usage|storage_byte_cost|storage_cost|storage_balance|storage_stak|STORAGE_"
                          r"|min_storage|required_storage|storage_deposit|bytes_for", re.I)
DEPOSIT_TERM = re.compile(r"attached_deposit|deposit|>=|<=|[<>]|balance")


def op_storage_staking(f: dict) -> str | None:
    code = f["code"]
    if not (STORAGE_CALL.search(code) or STORAGE_TERM.search(code)):
        return None
    b, root = _tree(code)
    edits = []
    for n in _walk(root):
        if n.type != "expression_statement":
            continue
        chk = _check_text(b, n)
        txt = _s(b, n)
        if chk and STORAGE_TERM.search(chk) and DEPOSIT_TERM.search(chk):
            edits.append(_del(b, n))
        elif n.named_children and n.named_children[0].type == "call_expression" and STORAGE_CALL.search(txt) \
                and "{" not in txt:
            edits.append(_del(b, n))
    return _drop_dead_lets(_apply(b, edits), code) if edits else None


def op_ft_receiver_trust(f: dict) -> str | None:
    if f["fn"] not in RECEIVERS or not PREDECESSOR.search(f["code"]):
        return None
    names = _predecessor_names(f)
    refs = re.compile(r"predecessor_account_id" + "".join(rf"|\b{re.escape(x)}\b" for x in names))
    return _delete_checks(f, lambda t: bool(refs.search(t)) and not SELF_CHECK.search(t), cleanup=False)


RECV = re.compile(r"\b(?:receiver\w*|recipient\w*|to|beneficiary\w*|new_owner\w*|target\w*|dest\w*|account_id)\b")
NOT_REGISTERED = re.compile(r"not\s+(?:been\s+|yet\s+)?registered|\bunregistered\b|not_registered|NotRegistered"
                            r"|ERR\w*REGISTER|no\s+storage\s+balance|storage_balance", re.I)
REG = re.compile(r"is_registered|storage_balance_of|\w*registered\w*\s*\(|\baccounts?\w*\s*\.\s*(?:contains_key|get)\s*\("
                 r"|account_exists|internal_get_account\w*\s*\(", re.I)


def op_unchecked_receiver(f: dict) -> str | None:
    code = f["code"]
    if not RECV.search(code) or HELPER_NAME.match(f["fn"]):
        return None
    b, root = _tree(code)
    callers = {name for _, name, val in _let_names(b, root)
               if re.search(r"(?:predecessor|signer)_account_id", _s(b, val))}
    caller = re.compile(r"(?:predecessor|signer)_account_id" + "".join(rf"|\b{re.escape(x)}\b" for x in callers))
    edits = [_del(b, n) for n, t in _checks(b, root)
             if (REG.search(t) or NOT_REGISTERED.search(_t(b, n))) and RECV.search(t) and not caller.search(t)
             and not re.search(r"already|exist", _t(b, n), re.I)]
    if not edits:
        for n in _walk(root):
            m = _method(b, n)
            if m and m[0] in ("expect", "unwrap_or_else") and NOT_REGISTERED.search(_t(b, m[2])) \
                    and RECV.search(_s(b, m[1])) and not caller.search(_s(b, m[1])):
                edits.append((m[1].end_byte, n.end_byte, b".unwrap_or_default()"))
                break
    return _drop_dead_lets(_apply(b, edits), code) if edits else None


PAGE_PARAMS = {"from_index", "limit", "offset", "from", "start", "skip", "page", "page_size", "take", "start_index"}
RANGE_MIN = [re.compile(r"^(\w+)\s*\.\.\s*(?:std::cmp::)?min\s*\(\s*\1\s*\+\s*(\w+)\s*,\s*(.+)\)$", re.S),
             re.compile(r"^(\w+)\s*\.\.\s*\(\s*\1\s*\+\s*(\w+)\s*\)\s*\.\s*min\s*\((.+)\)$", re.S)]


def _remove_pagination(f: dict) -> str | None:
    b, root = _tree(f["code"])
    fn = _fn_node(root)
    params = [p for p in fn.child_by_field_name("parameters").named_children if p.type == "parameter"]
    page = {_t(b, p.child_by_field_name("pattern")): p for p in params
            if _t(b, p.child_by_field_name("pattern")) in PAGE_PARAMS}
    if not {"limit", "page_size", "take"} & set(page):
        return None
    names = set(page)
    for _, name, val in _let_names(b, root):
        if any(re.search(rf"\b{x}\b", _s(b, val)) for x in names):
            names.add(name)
    mentions = re.compile("|".join(rf"\b{re.escape(x)}\b" for x in names))
    edits = []
    for n in _walk(fn.child_by_field_name("body")):
        m = _method(b, n)
        if m and m[0] in ("skip", "take") and mentions.search(_s(b, m[2])):
            s, e = m[1].end_byte, n.end_byte
            ls, le = _line_bounds(b, s)
            if not b[s:le].strip() and b[_line_bounds(b, e)[0]:e].strip().startswith(b"."):
                s = le
            edits.append((s, e, b""))
        elif n.type == "range_expression":
            for rx in RANGE_MIN:
                mm = rx.match(_t(b, n))
                if mm and mentions.search(mm.group(1)) and mentions.search(mm.group(2)):
                    edits.append((n.start_byte, n.end_byte, f"0..{mm.group(3).strip()}".encode()))
                    break
    if not edits:
        return None
    code = _drop_dead_lets(_apply(b, edits), f["code"])
    b, root = _tree(code)
    fn = _fn_node(root)
    body = _s(b, fn.child_by_field_name("body"))
    if any(re.search(rf"\b{re.escape(x)}\b", body) for x in page):
        return None
    plist = fn.child_by_field_name("parameters")
    kids = [c for c in plist.children if c.type not in ("line_comment", "block_comment")]
    pedits = []
    for i, c in enumerate(kids):
        if c.type == "parameter" and _t(b, c.child_by_field_name("pattern")) in page:
            if i >= 2 and kids[i - 1].type == ",":
                pedits.append((kids[i - 1].start_byte, c.end_byte, b""))
            elif i + 1 < len(kids) and kids[i + 1].type == ",":
                end = kids[i + 1].end_byte
                while end < len(b) and b[end:end + 1] in b" \n\t":
                    end += 1
                pedits.append((c.start_byte, end, b""))
            else:
                pedits.append((c.start_byte, c.end_byte, b""))
    return _apply(b, pedits)


def op_gas_dos(f: dict) -> str | None:
    if "prepaid_gas" in f["code"]:
        out = _delete_checks(f, lambda t: bool(re.search(r"prepaid_gas\s*\(", t)))
        if out:
            return out
    return _remove_pagination(f) if re.search(r"\blimit\b|page_size", f["code"]) else None


STALE = re.compile(r"stale|recency|max_age|price_age|publish_time|valid_time|max_delay", re.I)
TIME_CMP = re.compile(r"(?:timestamp|publish_time|updated_at|last_update|\bage\b|valid_until)\w*(?:\(\))?[^;,]{0,80}?[<>]"
                      r"|[<>]=?[^;,]{0,80}?(?:timestamp|publish_time|updated_at|last_update|\bage\b|valid_until)", re.I)
PRICE = re.compile(r"price|oracle|feed|exchange_rate", re.I)


def op_oracle_price(f: dict) -> str | None:
    s = strip_code(f["code"])
    if not PRICE.search(s):
        return None
    return _delete_checks(f, lambda t: bool(TIME_CMP.search(t)) and bool(STALE.search(t) or PRICE.search(t)))


OPERATORS = {
    "non_private_callback": op_non_private_callback, "unhandled_promise_result": op_unhandled_promise_result,
    "async_reentrancy": op_async_reentrancy, "missing_access_control": op_missing_access_control,
    "missing_one_yocto": op_missing_one_yocto, "signer_auth": op_signer_auth,
    "unguarded_upgrade": op_unguarded_upgrade, "unsafe_arithmetic": op_unsafe_arithmetic,
    "precision_rounding": op_precision_rounding, "storage_staking": op_storage_staking,
    "ft_receiver_trust": op_ft_receiver_trust, "unchecked_receiver": op_unchecked_receiver,
    "gas_dos": op_gas_dos, "oracle_price": op_oracle_price,
}


def mutate(f: dict) -> tuple[dict, list]:
    """Valid mutants {operator: code} of one function, and the operators whose output failed verification."""
    muts, failed = {}, []
    base = normalized(f["code"])
    for op, fn in OPERATORS.items():
        try:
            code = fn(f)
        except Exception:  # an operator bug on odd syntax counts as a failed mutant, never aborts the run
            code, failed = None, failed + [op]
        if code is None:
            continue
        if clean_parse(code) and normalized(code) != base and any(g["fn"] == f["fn"] for g in extract_functions(code)):
            muts[op] = code
        else:
            failed.append(op)
    return muts, failed


def select(cands: list, per_op: int, per_fn: int, rank: dict, seed: str) -> list:
    """(original id, operator) picks: deterministic shuffle, rarest operators first, caps per operator and per fn."""
    order = sorted(cands, key=lambda c: c["id"])
    random.Random(seed).shuffle(order)
    used, picked = collections.Counter(), []
    for c in order:
        n = 0
        for op in sorted(c["mutants"], key=lambda o: (used[o], rank.get(o, 99), o)):
            if n >= per_fn:
                break
            if used[op] < per_op:
                used[op] += 1
                n += 1
                picked.append((c["id"], op))
    return picked


# ---------- corpus pass ----------

def _hash(code: str) -> str:
    return hashlib.sha1(normalized(code).encode()).hexdigest()


def sample_id(group: str, path: str, fn: str, code: str) -> str:
    return hashlib.sha1(f"{group}|{path}|{fn}|{code}".encode()).hexdigest()


CONTRACT_MARK = re.compile(r"#\[\s*(?:near_sdk::)?(?:near_bindgen|ext_contract)\b|#\[\s*(?:near_sdk::)?near\s*(?:\]|\(\s*contract_state)"
                           r"|\benv::(?:predecessor_account_id|attached_deposit|promise_result|current_account_id)\s*\("
                           r"|PanicOnDefault")


def contract_files(root: Path) -> list[tuple[str, str]]:
    """(relative path, source) of .rs files in crates (nearest Cargo.toml dir) where some file shows contract code:
    #[near_bindgen] / #[near(contract_state)] / ext_contract / env:: caller and deposit APIs. Off-chain crates that only
    use near_sdk types (nodes, indexers, CLIs) are left out."""
    crates, srcs = set(), []
    for d, dirs, names in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
        for name in sorted(names):
            p = Path(d) / name
            if name == "Cargo.toml":
                crates.add(p.parent)
            elif name.endswith(".rs") and not p.is_symlink():
                try:
                    if p.stat().st_size <= 1_000_000:
                        srcs.append((p, p.read_text(errors="replace")))
                except OSError:
                    continue
    def crate_of(p: Path) -> Path:
        for parent in p.parents:
            if parent in crates or parent == root:
                return parent
        return root
    owner = {p: crate_of(p) for p, _ in srcs}
    live = {owner[p] for p, src in srcs if CONTRACT_MARK.search(src)}
    return [(str(p.relative_to(root)), src) for p, src in srcs if owner[p] in live]


def repo_candidates(row: dict) -> dict:
    """Every non-test function of a repo's near-sdk crates that some operator can mutate, with its mutants."""
    root = Path(row["local_path"])
    stats = collections.Counter()
    applied, failed_ops = collections.Counter(), collections.Counter()
    cands, hashes = [], set()
    for rel, src in contract_files(root):
        stats["files"] += 1
        for f in extract_functions(src, rel):
            if f["is_test"]:
                continue
            stats["fns"] += 1
            hashes.add(_hash(f["code"]))
            if not clean_parse(f["code"]):
                stats["fns_unparseable"] += 1
                continue
            muts, failed = mutate(f)
            failed_ops.update(failed)
            applied.update(list(muts) + failed)
            if muts:
                cands.append({"f": f, "mutants": muts})
    return {"repo": row["repo"], "cands": cands, "stats": stats, "applied": applied, "failed": failed_ops,
            "hashes": hashes}


def sample(f: dict, code: str, row: dict, **kw) -> dict:
    group = row["repo"].lower()
    attrs = f["attrs"]
    if code != f["code"]:
        g = next((g for g in extract_functions(code) if g["fn"] == f["fn"]), None)
        attrs = g["attrs"] if g else attrs
    return {"id": sample_id(group, f["path"], f["fn"], code), "code": code, "fn": f["fn"], "impl": f["impl"],
            "trait": f["trait"], "is_near_bindgen": f["is_near_bindgen"], "is_public": f["is_public"],
            "is_payable": "payable" in attrs, "attrs": attrs, "severity": None, "group": group,
            "repo": f"https://github.com/{row['repo']}", "commit": row.get("head_commit"), "path": f["path"],
            "date": None, **kw}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--min-stars", type=int, default=3)
    ap.add_argument("--limit", type=int, default=0, help="only the first N repos (smoke test)")
    a = ap.parse_args()
    rows = [json.loads(line) for line in open(REPOS_JSONL)]
    rows = [r for r in rows if (r.get("stars") or 0) >= a.min_stars or r.get("audited")]
    # canonical repos first: duplicated functions (forks, copies) stay with the audited / most-starred repo
    rows.sort(key=lambda r: (not r.get("audited"), -(r.get("stars") or 0), r["repo"].lower()))
    if a.limit:
        rows = rows[:a.limit]
    results = {}
    with Pool(a.workers) as pool:
        for i, res in enumerate(pool.imap_unordered(repo_candidates, rows, chunksize=1), 1):
            results[res["repo"]] = res
            if i % 25 == 0:
                print(f"{i}/{len(rows)} repos", file=sys.stderr, flush=True)
    stats, applied, failed = collections.Counter(), collections.Counter(), collections.Counter()
    seen_orig, seen_mut = set(), set()
    kept, dup_orig, dup_mut, conflicts = {}, 0, 0, 0
    real = set().union(*(res["hashes"] for res in results.values()))  # every extracted function in the corpus
    for r in rows:
        res = results[r["repo"]]
        stats.update(res["stats"])
        applied.update(res["applied"])
        failed.update(res["failed"])
        cands = []
        for c in res["cands"]:
            h = normalized(c["f"]["code"])
            if h in seen_orig:
                dup_orig += 1
                continue
            seen_orig.add(h)
            muts = {}
            for op, code in c["mutants"].items():
                mh = normalized(code)
                if _hash(code) in real:  # same code exists unmutated somewhere: label conflict with corpus negatives
                    conflicts += 1
                    continue
                if mh in seen_mut:
                    dup_mut += 1
                    continue
                seen_mut.add(mh)
                muts[op] = code
            if muts:
                c["id"] = sample_id(r["repo"].lower(), c["f"]["path"], c["f"]["fn"], c["f"]["code"])
                c["mutants"] = muts
                cands.append(c)
        kept[r["repo"]] = cands
    avail = collections.Counter(op for cs in kept.values() for c in cs for op in c["mutants"])
    rank = {op: i for i, (op, _) in enumerate(sorted(avail.items(), key=lambda x: (x[1], x[0])))}
    per_op, per_repo = collections.Counter(), collections.Counter()
    n_orig = 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w") as out:
        for r in rows:
            cands = {c["id"]: c for c in kept[r["repo"]]}
            picks = collections.defaultdict(list)
            for oid, op in select(list(cands.values()), PER_OP, PER_FN, rank, seed=r["repo"].lower()):
                picks[oid].append(op)
            for oid, ops in picks.items():
                c = cands[oid]
                out.write(json.dumps(sample(c["f"], c["f"]["code"], r, label=0, vuln_class=None,
                                            source="mutation_original", evidence=None, pair_id=oid,
                                            operator=None)) + "\n")
                n_orig += 1
                for op in ops:
                    out.write(json.dumps(sample(c["f"], c["mutants"][op], r, label=1, vuln_class=op,
                                                source="mutation", evidence=f"mutation:{op}", pair_id=oid,
                                                operator=op)) + "\n")
                    per_op[op] += 1
                    per_repo[r["repo"]] += 1
    write_report(rows, stats, applied, failed, avail, per_op, per_repo, n_orig, dup_orig, dup_mut, conflicts)
    print(f"wrote {sum(per_op.values())} mutants + {n_orig} originals -> {OUT}", file=sys.stderr)


def write_report(rows, stats, applied, failed, avail, per_op, per_repo, n_orig, dup_orig, dup_mut, conflicts) -> None:
    lines = ["# Mutation samples", "",
             f"Source repos: {len(rows)} (stars >= 3 or audited). Contract .rs files: {stats['files']}. "
             f"Non-test functions: {stats['fns']} (unparseable originals skipped: {stats['fns_unparseable']}).", "",
             f"Rows: {sum(per_op.values())} mutants (label 1, source `mutation`) + {n_orig} originals "
             f"(label 0, source `mutation_original`). `pair_id` of every row = id of the original.", "",
             f"Caps: {PER_OP} mutants per (repo, operator), {PER_FN} per original function; rarer operators are "
             f"picked first. Duplicate originals across repos dropped (normalized code, canonical repo first): "
             f"{dup_orig}; duplicate mutants dropped: {dup_mut}; mutants identical to an unmutated function elsewhere in "
             f"the corpus dropped (label conflict): {conflicts}.", "",
             "| operator (= vuln_class) | applicable | failed verification | failure rate | unique after dedupe "
             "| emitted |", "|---|---:|---:|---:|---:|---:|"]
    for op in OPERATORS:
        rate = failed[op] / applied[op] if applied[op] else 0.0
        lines.append(f"| {op} | {applied[op]} | {failed[op]} | {rate:.1%} | {avail[op]} | {per_op[op]} |")
    lines += ["", "Failed verification = the mutant did not parse cleanly with tree-sitter, was identical to the "
              "original after normalization, or no longer extracted as the same function (or the operator raised).",
              "", f"## Mutants per repo (top 40 of {len(per_repo)})", "", "| repo | mutants |", "|---|---:|"]
    lines += [f"| {repo} | {n} |" for repo, n in per_repo.most_common(40)]
    lines += ["", METHOD]
    REPORT.write_text("\n".join(lines) + "\n")


METHOD = """## Method

Functions come from `near.analyzer.extract_functions` over .rs files of crates (nearest Cargo.toml) in which some file
shows contract code (`#[near_bindgen]`, `#[near(contract_state)]`, `ext_contract`, `env::predecessor_account_id()` /
`attached_deposit()` / `promise_result()`, `PanicOnDefault`); off-chain crates that only use near_sdk types are skipped.
Test functions (`is_test`) are skipped. Each operator edits the function's tree-sitter tree (statement deletion keeps
indentation, drops attached `//` comments and lets that became unused) and applies only when its protection is present:

| operator | edit |
|---|---|
| non_private_callback | callbacks only: drop `#[private]` and `predecessor == current_account_id` / `assert_self()` guards |
| unhandled_promise_result | drop `require!(is_promise_success())`-style guards; empty the failure arm / branch of a match or if on `promise_result` / `is_promise_success` / `#[callback_result]` when it restores state |
| async_reentrancy | non-callback fn with an external call and `.then(...)`: delete the state deduction (`self.x -= ..`, `self.internal_withdraw(..)`, `lock_*`, ...) that precedes the call |
| missing_access_control | drop owner/role guards (`assert_owner()`, `require!(predecessor == self.owner_id)`, `#[only(..)]`, `#[access_control_any]`, `#[private]` on non-callbacks) and predecessor equality checks; skips upgrade paths and guard helpers |
| missing_one_yocto | drop `assert_one_yocto()` / 1-yocto deposit guards |
| signer_auth | `predecessor_account_id()` -> `signer_account_id()` in guards, in the `let caller = ..` a guard uses, or (public `&mut self` non-callback fns) in the first statement that uses the caller |
| unguarded_upgrade | upgrade/migrate/self-deploy fns: drop auth and self guards and `#[private]` |
| unsafe_arithmetic | one amount expression: `x.checked_op(y).unwrap()/expect/ok_or()?` or `saturating_op` -> `x op y`; else strip `as u128` widening from a multiplication |
| precision_rounding | one spot: `div_ceil` / `ceil_div` / `(a + b - 1) / b` / `Rounding::Up` -> floor; else `checked_mul(b)..checked_div(c)` swapped; else `a * b / c` -> `a / c * b` on amounts |
| storage_staking | drop storage-cost guards and `refund_deposit(..)` / `*_storage_*` charge calls |
| ft_receiver_trust | `ft_on_transfer` / `nft_on_transfer` / `mt_on_transfer` / `nft_on_approve`: drop guards on the predecessor token |
| unchecked_receiver | drop registration guards on a receiver (not on the caller); else `.expect("..not registered")` -> `.unwrap_or_default()` |
| gas_dos | drop `prepaid_gas()` guards; else remove `.skip/.take` pagination and its `from_index`/`limit` params |
| oracle_price | drop guards that compare a price timestamp / age against the clock |

A mutant is kept only if tree-sitter parses it without ERROR/MISSING nodes, it differs from the original after
stripping comments and whitespace, and it still extracts as the same function.

## Limits (read before using these rows)

- Labels are by construction. The original is presumed safe (it is unaudited corpus code); a mutant is not
  checked for exploitability in context: the removed check may be repeated elsewhere (caller, helper, trait default),
  the function may be a mock/example contract, an unbounded view (gas_dos) only fails RPC calls, and a callback
  without state effects is low-impact without `#[private]`. Precision was judged by reading roughly 120 random diffs
  across all operators during development and is not measured.
- Each mutant differs from its original by a few tokens. Mutation recall therefore overstates real-world recall:
  report it separately from audit/incident/fix_commit results (as PLAN.md says).
- Originals are emitted only for functions that carry a protection, so label-0 `mutation_original` rows are
  guarded functions; unguarded safe functions (views, internal helpers) must come from the corpus negatives, or a model
  learns that a missing guard means vulnerable.
- Small classes: oracle_price and unchecked_receiver have few rows; async_reentrancy covers only the
  deduction-removed-before-call form (the callback is not edited). Rollback removal in a failure branch is labelled
  unhandled_promise_result. The `as u64` narrowing variant is not implemented; widening removal is used instead.
- Exact duplicates are removed across repos (canonical repo first) and mutants equal to a real function are dropped,
  but near-duplicates (copied contracts with small edits) can remain in different groups; the assembly step's
  normalized-token near-duplicate check across the split still applies.
- `severity` and `date` are null; `commit` is the clone's HEAD; `evidence` is `mutation:<operator>`; `pair_id` of the
  original is its own id.

Run: `uv run python -m near.collect.mutate` (about 25 s on 16 workers). Tests: `uv run python -m unittest
near.collect.test_mutate`.
"""


if __name__ == "__main__":
    main()
