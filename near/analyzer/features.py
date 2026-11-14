"""Per-function numeric features: detector hit counts per vuln_class plus structural counts. Same keys for every fn."""
from __future__ import annotations

import re

from .detectors import (COLL_INSERT, COLL_REMOVE, DEPLOY, EXT_CALL, NARROW_AS, SEVERITY, THEN, WRITE_ASSIGN, YOCTO,
                        context, detect_ctx)

VULN_CLASSES = ("non_private_callback", "unhandled_promise_result", "async_reentrancy", "missing_access_control",
                "missing_one_yocto", "signer_auth", "unguarded_upgrade", "unsafe_arithmetic", "precision_rounding",
                "storage_staking", "ft_receiver_trust", "unchecked_receiver", "gas_dos", "oracle_price", "logic_error")

COUNTS = {  # feature -> pattern counted in the stripped body
    "n_promises": re.compile(r"Promise::new\s*\(|::\s*ext\s*\(|\bext_\w+\s*::\s*\w+\s*\(|promise_(?:batch_)?create"),
    "n_then": THEN,
    "n_function_calls": re.compile(r"\.\s*function_call\w*\s*\("),
    "n_collection_inserts": COLL_INSERT,
    "n_collection_removes": COLL_REMOVE,
    "n_asserts": re.compile(r"\b(?:assert\w*|require|debug_assert\w*)!\s*\(|\bpanic(?:_str)?!?\s*\(|env::panic"),
    "n_requires": re.compile(r"\brequire!\s*\("),
    "n_unwraps": re.compile(r"\.\s*(?:unwrap|expect)\s*\("),
    "n_checked_ops": re.compile(r"\.\s*(?:checked|saturating)_\w+\s*\("),
    "n_u128_ops": re.compile(r"\bu128\b|\bU128\b|\bBalance\b|\bNearToken\b|\.0\s*[+\-*/]"),
    "n_arith_ops": re.compile(r"(?<=[\w)\]])\s*[+\-*/%]\s*(?=[\w(])|[+\-*/]="),
    "n_div": re.compile(r"(?<=[\w)\]])\s*/\s*(?=[\w(])|/="),
    "n_casts": re.compile(r"\bas\s+(?:[iu](?:8|16|32|64|128|size)|f32|f64)\b"),
    "n_narrow_casts": NARROW_AS,
    "n_loops": re.compile(r"\b(?:for|while|loop)\b"),
    "n_branches": re.compile(r"\b(?:if|match)\b"),
    "n_iter_self": re.compile(r"\bself\.[\w.]+\.(?:iter|iter_mut|keys|values|to_vec)\s*\("),
    "n_external_calls": re.compile(r"\bext_\w+\s*::|(?<!Self)::\s*ext\s*\((?!\s*env::current_account_id)"),
    "n_self_calls": re.compile(r"\bself\.\w+\s*\("),
    "n_ft_calls": re.compile(r"\b(?:ft|nft|mt)_(?:transfer|transfer_call|batch_transfer)\b"),
    "transfers": re.compile(r"\.\s*transfer\s*\(\s*(?!&)"),
    "n_unsafe": re.compile(r"\bunsafe\b"),
}
FLAGS = {  # feature -> pattern whose presence (0/1) is the feature
    "uses_predecessor": re.compile(r"predecessor_account_id\s*\("),
    "uses_signer": re.compile(r"signer_account_id\s*\("),
    "uses_signer_pk": re.compile(r"signer_account_pk\s*\("),
    "uses_current_account": re.compile(r"current_account_id\s*\("),
    "uses_assert_one_yocto": YOCTO,
    "uses_attached_deposit": re.compile(r"attached_deposit\s*\("),
    "uses_prepaid_gas": re.compile(r"prepaid_gas\s*\(|used_gas\s*\("),
    "uses_promise_result": re.compile(r"promise_result|is_promise_success|PromiseResult|PromiseError"),
    "uses_checked_math": re.compile(r"\.\s*(?:checked|saturating)_\w+\s*\("),
    "uses_env_storage_usage": re.compile(r"storage_usage\s*\("),
    "uses_storage_byte_cost": re.compile(r"storage_byte_cost|STORAGE_PRICE_PER_BYTE"),
    "uses_block_timestamp": re.compile(r"block_timestamp\w*\s*\("),
    "uses_block_height": re.compile(r"block_height\s*\(|block_index\s*\(|epoch_height\s*\("),
    "uses_random_seed": re.compile(r"random_seed\w*\s*\("),
    "deploy_contract": DEPLOY,
    "create_account": re.compile(r"create_account\s*\("),
    "add_key": re.compile(r"add_(?:full_access|access)_key\w*\s*\("),
    "delete_account": re.compile(r"delete_account\s*\("),
    "uses_float": re.compile(r"\bf(?:32|64)\b"),
    "uses_log": re.compile(r"\blog!\s*\(|env::log"),
    "uses_state_read": re.compile(r"state_read\s*\("),
    "uses_price": re.compile(r"\bprice", re.I),
    "returns_promise": None,  # computed from the signature
}
STRUCT = ("n_lines", "n_params", "is_public", "is_payable", "is_private", "is_view", "is_mut", "is_static", "is_init",
          "is_near_bindgen", "is_entry", "is_callback", "is_trait_impl", "is_receiver", "has_auth", "n_state_writes")
FEATURE_KEYS = (tuple(f"hit_{c}" for c in VULN_CLASSES) + ("n_hits", "max_severity") + STRUCT
                + tuple(COUNTS) + tuple(FLAGS))


def features_ctx(ctx: dict, hits: list[dict]) -> dict[str, float]:
    fn, body, sig = ctx["fn"], ctx["body"], ctx["sig"]
    out = dict.fromkeys(FEATURE_KEYS, 0.0)
    for h in hits:
        out[f"hit_{h['vuln_class']}"] += 1
    out["n_hits"] = float(len(hits))
    out["max_severity"] = float(max((SEVERITY.get(h["severity"], 0) for h in hits), default=0))
    params = re.sub(r"<[^<>]*>", "", sig[sig.find("("):sig.rfind(")") + 1] if "(" in sig else "")
    out.update({
        "n_lines": float(ctx["s"].count("\n") + 1),
        "n_params": float(len(re.findall(r"\b\w+\s*:(?!:)", params))),
        "is_public": float(bool(fn.get("is_public"))), "is_payable": float(ctx["payable"]),
        "is_private": float(ctx["private"]), "is_view": float(ctx["view"]), "is_mut": float(ctx["mut"]),
        "is_static": float(not ctx["has_self"]), "is_init": float(ctx["init"]),
        "is_near_bindgen": float(bool(fn.get("is_near_bindgen"))), "is_entry": float(ctx["entry"]),
        "is_callback": float(ctx["callback"]), "is_trait_impl": float(bool(fn.get("trait"))),
        "is_receiver": float(ctx["name"] in ("ft_on_transfer", "nft_on_transfer", "mt_on_transfer", "nft_on_approve")),
        "has_auth": float(ctx["auth"]),
        "n_state_writes": float(len(WRITE_ASSIGN.findall(body))),
    })
    for k, rx in COUNTS.items():
        out[k] = float(len(rx.findall(body)))
    for k, rx in FLAGS.items():
        out[k] = float(bool(rx.search(body))) if rx is not None else 0.0
    out["returns_promise"] = float(bool(re.search(r"->\s*(?:near_sdk::)?(?:Promise|PromiseOrValue)\b", sig)))
    if EXT_CALL.search(body) is None and out["n_promises"] == 0:
        out["n_external_calls"] = 0.0
    return out


def features(fn: dict, file_src: str | None = None) -> dict[str, float]:
    """Stable dict of floats (FEATURE_KEYS order). Never raises; all zeros if the function can't be analyzed."""
    try:
        ctx = context(fn, file_src)
        return features_ctx(ctx, detect_ctx(ctx))
    except Exception:
        return dict.fromkeys(FEATURE_KEYS, 0.0)
