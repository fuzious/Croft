"""Attack metadata and observed-pattern categories; never predictive features or proof of intent."""
from __future__ import annotations

import json
from pathlib import Path

TAXONOMY = json.loads((Path(__file__).parent / "fixtures/attack_taxonomy.json").read_text())
FAMILIES = {row["id"]: row for row in TAXONOMY["families"]}
FAMILY_IDS = tuple(FAMILIES)

CAMPAIGN_FAMILIES = {
    "oct_exploit": "callback_accounting",
    "apr_oog_attempts": "resource_exhaustion",
    "may_admin_fuzzing": "access_control",
    "may_token_spoof": "token_spoofing",
    "team_regression": "callback_accounting",
    "2026-10-01 NEAR Intents deposit-notify ghost balance exploit (USDT-BSC via HOT Omni)": "callback_accounting",
    "2026-04-03 notify callback out-of-gas attempts (CallbackOogReturn), refunds held": "resource_exhaustion",
    "2026-05-20..21 fake-token / token-id spoof fuzzing of intents.near": "token_spoofing",
    "2026-05-23..31 admin/private-method fuzzing of intents.near (test1779579480756.near)": "access_control",
    "2026-10-02 defuse-ops post-fix notify regression tests (team, not attacker)": "callback_accounting",
    "rhea_margin_circular_swap_2026_04": "accounting_logic",
    "skyward_duplicate_redemption_2022_11": "share_accounting",
    "notify_refund_log_overflow": "callback_accounting",
    "notify_refund_overask": "callback_accounting",
    "notify_receiver_failure": "callback_accounting",
    "callback_low_gas": "resource_exhaustion",
    "direct_private_call": "access_control",
    "admin_probe": "access_control",
    "token_spoof_direct_on_transfer": "token_spoofing",
}

RULE_FAMILIES = {
    "failed_resolve_callback": "callback_accounting",
    "credit_kept": "callback_accounting",
    "refund_exceeds_deposit": "callback_accounting",
    "accounting_credit_exceeds_backing": "callback_accounting",
    "history_withdrawal_after_callback": "callback_accounting",
    "history_withdrawal_after_retained_credit": "callback_accounting",
    "private_method_direct": "access_control",
    "admin_method_non_role": "access_control",
    "history_repeated_failed_private_probes": "access_control",
    "log_limit": "resource_exhaustion",
    "many_token_ids": "resource_exhaustion",
    "callback_oog": "resource_exhaustion",
    "return_value_limit": "resource_exhaustion",
}


def family_for_campaign(name: str | None) -> str | None:
    """Map explicit reviewed labels; do not infer a cause from names in transaction contents."""
    if not isinstance(name, str):
        return None
    if name in CAMPAIGN_FAMILIES:
        return CAMPAIGN_FAMILIES[name]
    name = name.split(" / ", 1)[0]
    if name.startswith("sandbox:"):
        name = name.removeprefix("sandbox:")
    return name if name in FAMILIES else CAMPAIGN_FAMILIES.get(name)


def classify_metadata(meta: dict) -> dict:
    """Summarize supplied dataset labels, without verifying them or promoting associated activity to attacks."""
    family = next((found for key in ("family", "attack_family", "campaign")
                   if (found := family_for_campaign(meta.get(key)))), None)
    role, label = meta.get("role"), meta.get("label")
    positive = type(label) is int and label == 1 or label == "attack"
    negative = type(label) is int and label == 0 or label == "benign"
    if role in ("setup", "cashout", "setup_funding_via_intents"):
        outcome, target = "associated_activity", None
    elif positive and role in ("exploit", "attempt"):
        outcome, target = role, 1
    elif negative and role in (None, "benign", "team_regression_test"):
        outcome, target = "benign", 0
    else:
        outcome, target = "unknown", None
    source = str(meta.get("source") or "")
    provenance = ("sandbox" if source == "sandbox" else "generated" if source.startswith(("generated", "synthetic"))
                  else "on_chain" if source.startswith(("fastnear", "collector", "scout", "mainnet")) else "unknown")
    return {"category": family, "outcome": outcome, "supervised_label": target, "provenance": provenance}


def categories_for_rules(rule_hits: list[dict]) -> list[dict]:
    """Categories for matched evidence only; a generic failure, transfer or token name assigns no cause."""
    matched: dict[str, set[str]] = {}
    for hit in rule_hits:
        rule = hit.get("rule")
        family = RULE_FAMILIES.get(rule)
        if family:
            matched.setdefault(family, set()).add(rule)
    return [{"id": family, "label": FAMILIES[family]["label"], "rules": sorted(matched[family]),
             "evidence_basis": "Observed pattern category; not a verified root cause or proof of malicious intent."}
            for family in FAMILY_IDS if family in matched]
