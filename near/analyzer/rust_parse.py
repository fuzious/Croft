"""Extract every Rust function from a source file with tree-sitter, with the NEAR context the detectors need:
enclosing impl/trait, whether that impl is exported (#[near_bindgen] / near-sdk 5 #[near]), fn attributes."""
from __future__ import annotations

import re
import textwrap

import tree_sitter_rust
from tree_sitter import Language, Parser

PARSER = Parser(Language(tree_sitter_rust.language()))
CONTAINERS = {"mod_item", "impl_item", "trait_item"}
BINDGEN = {"near_bindgen", "near"}
TEST_ATTRS = {"test", "rstest", "bench", "test_case"}
CFG_TEST = re.compile(r"#\s*\[\s*cfg\s*\(\s*(?:all\s*\(\s*)?test\b")


def _text(b: bytes, node) -> str:
    return b[node.start_byte:node.end_byte].decode("utf8", errors="replace")


def _attr_name(b: bytes, attr_item) -> str | None:
    """Bare name of `#[name(...)]` / `#[path::name]`; `cfg_attr(.., x)` yields `x` when x is a bindgen attr."""
    attr = next((c for c in attr_item.named_children if c.type == "attribute"), None)
    if attr is None or not attr.named_children:
        return None
    name = _text(b, attr.named_children[0]).split("::")[-1].strip()
    if name == "cfg_attr":
        args = _text(b, attr)
        hit = next((x for x in ("near_bindgen", "near") if f", {x}" in args or f",{x}" in args), None)
        return hit or name
    return name


def _is_doc(b: bytes, node) -> bool:
    t = b[node.start_byte:node.start_byte + 4]
    return (t.startswith(b"///") and not t.startswith(b"////")) or (t.startswith(b"/**") and t != b"/**/")


def _base_name(b: bytes, node) -> str | None:
    if node is None:
        return None
    return _text(b, node).split("<")[0].split("::")[-1].strip() or None


def _code(b: bytes, start: int, end: int) -> str:
    """Source from `start` to `end`, taken from the start of the line when only indentation precedes it, dedented."""
    line_start = b.rfind(b"\n", 0, start) + 1
    if not b[line_start:start].strip():
        start = line_start
    return textwrap.dedent(b[start:end].decode("utf8", errors="replace"))


def _fn_record(b: bytes, node, pending: list, ctx: dict, path: str) -> dict | None:
    name = node.child_by_field_name("name")
    if name is None or node.child_by_field_name("body") is None:
        return None
    attrs = [a for a in (_attr_name(b, p) for p in pending if p.type == "attribute_item") if a]
    params = node.child_by_field_name("parameters")
    if params is not None:  # #[callback_result], #[callback_unwrap], #[serializer(..)] on parameters
        attrs += [a for a in (_attr_name(b, c) for c in params.children if c.type == "attribute_item") if a]
    vis = next((c for c in node.children if c.type == "visibility_modifier"), None)
    start = pending[0].start_byte if pending else node.start_byte
    attrs = list(dict.fromkeys(attrs))
    is_test = (ctx["test"] or bool(TEST_ATTRS & set(attrs)) or any(CFG_TEST.match(_text(b, p)) for p in pending)
               or "/tests/" in f"/{path}")
    return {
        "fn": _text(b, name), "impl": ctx["impl"], "trait": ctx["trait"], "is_near_bindgen": ctx["bindgen"],
        "attrs": attrs, "code": _code(b, start, node.end_byte),
        "start_line": (pending[0] if pending else node).start_point[0] + 1, "end_line": node.end_point[0] + 1,
        # trait impl methods carry no `pub` but are as public as the trait (exported under #[near_bindgen])
        "is_public": (vis is not None and _text(b, vis) == "pub") or (ctx["trait"] is not None and ctx["impl_kind"]),
        "is_payable": "payable" in attrs, "is_test": is_test, "path": path,
    }


def extract_functions(src: str, path: str = "") -> list[dict]:
    """All fns with a body: inherent/trait impls, trait default methods, free fns, fns in mod blocks.
    Never raises; on syntax errors returns whatever tree-sitter recovered."""
    try:
        b = src.encode("utf8", errors="replace") if isinstance(src, str) else bytes(src)
        root = PARSER.parse(b).root_node
    except Exception:
        return []
    out: list[dict] = []
    top = {"impl": None, "trait": None, "bindgen": False, "impl_kind": False, "test": False}
    stack = [(root, top)]
    while stack:
        parent, ctx = stack.pop()
        pending: list = []
        for node in parent.children:
            t = node.type
            if t == "attribute_item":
                pending.append(node)
                continue
            if t in ("line_comment", "block_comment"):
                if pending or _is_doc(b, node):
                    pending.append(node)
                continue
            if t == "function_item":
                rec = _fn_record(b, node, pending, ctx, path)
                if rec:
                    out.append(rec)
            elif t in CONTAINERS or t in ("ERROR", "declaration_list"):
                attrs = {_attr_name(b, p) for p in pending if p.type == "attribute_item"}
                test = ctx["test"] or any(CFG_TEST.match(_text(b, p)) for p in pending)
                body = node if t in ("ERROR", "declaration_list") else node.child_by_field_name("body")
                if t == "impl_item":
                    sub = {"impl": _base_name(b, node.child_by_field_name("type")),
                           "trait": _base_name(b, node.child_by_field_name("trait")),
                           "bindgen": bool(attrs & BINDGEN), "impl_kind": True, "test": test}
                elif t == "trait_item":
                    sub = {"impl": None, "trait": _base_name(b, node.child_by_field_name("name")),
                           "bindgen": False, "impl_kind": False, "test": test}
                elif t == "mod_item":
                    sub = {**top, "test": test}
                else:
                    sub = ctx
                if body is not None:
                    stack.append((body, sub))
            pending = []
    out.sort(key=lambda r: r["start_line"])
    return out
