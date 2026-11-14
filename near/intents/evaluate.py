"""Evaluate the frozen NEAR Intents model (near/models/intents_v1.*): sealed test normals, campaign case studies and
the rules / anomaly / combined ablation.

The test slice (normals from near.intents.model.TEST_FIRST on) is sealed: `run` scores it once and refuses to run
again once near/intents/reports/evaluation.json exists, unless --rescore is given (recorded in the output). It records
the sha256 of the freeze manifest it scored with, so the thresholds provably predate the test numbers.

    .venv/bin/python -m near.intents.evaluate run      # writes reports/evaluation.{json,md}
    .venv/bin/python -m near.intents.evaluate tables   # re-renders evaluation.md from evaluation.json, scores nothing
    .venv/bin/python -m near.intents.evaluate paused   # post-hoc: test false alarms with / without paused-contract txs
"""
from __future__ import annotations

import argparse
import datetime
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from near.intents import model as md
from near.intents.collect import iter_jsonl_gz

REPORTS = Path(__file__).parent / "reports"
EVAL_JSON = REPORTS / "evaluation.json"
EVAL_MD = REPORTS / "evaluation.md"
TXS_PER_DAY = 97_000
LEVELS = ("high", "medium+")
CAMPAIGNS = (  # incident prefix -> short name
    ("2026-10-01", "oct_exploit"), ("2026-04-03", "apr_oog_attempts"), ("2026-04-16", "rhea_funding"),
    ("2026-05-20", "may_token_spoof"), ("2026-05-23", "may_admin_fuzzing"), ("2026-10-02", "team_regression"),
)
SYSTEMS = ("rules_only", "anomaly_only", "combined")


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [float("nan"), float("nan")]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [0.0 if k == 0 else float(max(0.0, c - h)), 1.0 if k == n else float(min(1.0, c + h))]


def rate(k: int, n: int) -> dict:
    return {"k": int(k), "n": int(n), "rate": k / n if n else float("nan"), "ci95": wilson(int(k), int(n))}


def campaign_key(campaign: str | None, role: str | None) -> str:
    short = next((s for p, s in CAMPAIGNS if (campaign or "").startswith(p)), campaign or "unknown")
    return f"{short} / {role}"


def system_labels(art: dict, scores: np.ndarray, rule_sev: np.ndarray) -> dict[str, np.ndarray]:
    """Labels of the three ablation systems on the same rows. anomaly_only uses thresholds calibrated without rules
    (same rate targets); rules_only uses no anomaly score."""
    never = {"high": np.inf, "medium": np.inf}
    return {"rules_only": md.labels_for(rule_sev, scores, never),
            "anomaly_only": md.labels_for(np.zeros_like(rule_sev), scores, art["thresholds_anomaly_only"]),
            "combined": md.labels_for(rule_sev, scores, art["thresholds"])}


def level_counts(lab: np.ndarray) -> dict:
    n = len(lab)
    hi = int((lab == "high").sum())
    mp = int(np.isin(lab, ["high", "medium"]).sum())
    return {"n": n, "high": hi, "medium": mp - hi, "missed": n - mp, "high_rate": rate(hi, n),
            "medium_plus_rate": rate(mp, n)}


def false_alarms(lab: np.ndarray, groups: np.ndarray | None = None) -> dict:
    out = {"all": level_counts(lab)}
    if groups is not None:
        for g in sorted(set(groups.tolist())):
            out[g] = level_counts(lab[groups == g])
    for v in out.values():
        for lvl, key in (("high", "high_rate"), ("medium+", "medium_plus_rate")):
            r = v[key]
            v[f"alerts_per_day_{lvl}"] = {"est": r["rate"] * TXS_PER_DAY,
                                          "ci95": [x * TXS_PER_DAY for x in r["ci95"]]}
    return out


def rules_fired(rules: list, idx) -> dict:
    c = Counter(f"{r} ({s})" for i in idx for r, s in rules[i])
    return dict(c.most_common())


def check_score_tx_agrees(art: dict, L: dict, scores: np.ndarray) -> dict:
    """score_tx (the deployed path) against the vectorized cache path on every labelled transaction."""
    lab = md.labels_for(L["rule_sev"], scores, art["thresholds"])
    pos = {h: i for i, h in enumerate(L["ids"].tolist())}
    bad = 0
    n = 0
    for tx in iter_jsonl_gz(md.LABELLED):
        i = pos[tx["transaction"]["hash"]]
        r = md.score_tx(tx, art)
        n += 1
        if r["label"] != lab[i] or not np.isclose(r["anomaly_score"], scores[i]):
            bad += 1
    return {"n": n, "mismatches": bad}


def run(rescore: bool = False) -> dict:
    prior = json.loads(EVAL_JSON.read_text()) if EVAL_JSON.exists() else None
    if prior and not rescore:
        raise SystemExit(f"{EVAL_JSON} exists: the test slice was already scored. Use `tables`, or --rescore "
                         f"(recorded) if you must.")
    man_path = md.OUT / f"{md.TAG}.json"
    art = md.load_artifact()
    cache = md.load_cache()
    man = json.loads(man_path.read_text())
    if cache["normals_sha256"] != man["normals_sha256"]:
        raise SystemExit("normals file changed since the freeze")
    N, L = cache["normals"], cache["labelled"]
    sp = md.split_masks(N["month"])
    out = {"manifest_sha256": md.sha256_file(man_path), "pkl_sha256": man["pkl_sha256"], "kind": art["kind"],
           "thresholds": art["thresholds"], "thresholds_anomaly_only": art["thresholds_anomaly_only"],
           "scored_at": md.utc_now(), "rescored": (prior or {}).get("rescored", -1) + 1 if prior else 0,
           "txs_per_day": TXS_PER_DAY}

    # development-period normals (train + calibration): rules only plus combined, for context
    dev = {}
    for part in ("train", "calib"):
        m = sp[part]
        s = md.score_matrix(art, N["X"][m], N["flow"][m].astype(str))
        labs = system_labels(art, s, N["rule_sev"][m])
        dev[part] = {sys: false_alarms(labs[sys], N["flow"][m].astype(str)) for sys in SYSTEMS}
        dev[part]["rules_fired"] = rules_fired(N["rules"], np.where(m)[0])
    out["dev_normals"] = dev

    # sealed test normals
    m = sp["test"]
    idx = np.where(m)[0]
    flows = N["flow"][m].astype(str)
    s = md.score_matrix(art, N["X"][m], flows)
    labs = system_labels(art, s, N["rule_sev"][m])
    src = np.array(["scout_seed" if str(x).startswith("fastnear-seed") else "collector" for x in N["source"][m]])
    test = {"n": int(m.sum()), "by_month": dict(Counter(N["month"][m].tolist())),
            "by_source": dict(Counter(src.tolist()))}
    for sys in SYSTEMS:
        test[sys] = {"by_flow": false_alarms(labs[sys], flows), "by_source": false_alarms(labs[sys], src),
                     "failing_vs_ok": false_alarms(labs[sys], np.where(N["failed"][m], "failed", "ok"))}
    test["rules_fired"] = rules_fired(N["rules"], idx)
    alerts = np.where(labs["combined"] != "low")[0]
    test["combined_alerts"] = [
        {"tx": N["ids"][idx[i]], "flow": flows[i], "label": labs["combined"][i], "anomaly_score": float(s[i]),
         "pct": md.percentile(art, s[i]), "rules": N["rules"][idx[i]], "failed": bool(N["failed"][idx[i]]),
         "source": str(N["source"][idx[i]])} for i in alerts]
    out["test_normals"] = test

    # campaign case studies (all held out from training and calibration)
    sL = md.score_matrix(art, L["X"], L["flow"].astype(str))
    labsL = system_labels(art, sL, L["rule_sev"])
    keys = np.array([campaign_key(c, r) for c, r in zip(L["campaign"], L["role"])])
    cases = {}
    for k in sorted(set(keys.tolist())):
        sel = np.where(keys == k)[0]
        cases[k] = {"n": len(sel), "by_flow": dict(Counter(L["flow"][sel].tolist())),
                    "rules_fired": rules_fired(L["rules"], sel),
                    **{sys: level_counts(labsL[sys][sel]) for sys in SYSTEMS},
                    "anomaly_pct_median": float(np.median([md.percentile(art, x) for x in sL[sel]]))}
        if sel.size and np.any(L["failed"][sel]):
            f = sel[L["failed"][sel]]
            cases[k]["combined_failing_only"] = level_counts(labsL["combined"][f])
    out["cases"] = cases
    out["score_tx_check"] = check_score_tx_agrees(art, L, sL)

    REPORTS.mkdir(parents=True, exist_ok=True)
    EVAL_JSON.write_text(json.dumps(out, indent=1, default=str))
    EVAL_MD.write_text(tables(out))
    print(f"wrote {EVAL_JSON} and {EVAL_MD}")
    return out


# --- post-hoc diagnostic -------------------------------------------------------------------------------------------

PAUSED = "Method is paused"


def paused_failure(tx: dict) -> bool:
    """A receipt failed because the called contract was paused (Pausable)."""
    return any(PAUSED in json.dumps(r.get("execution_outcome", {}).get("outcome", {}).get("status", {}))
               for r in tx.get("receipts") or [])


def paused(ev: dict) -> dict:
    """Post-hoc, after the sealed run: the test false-alarm rates split by whether the tx failed on a paused
    contract (intents.near was paused during the 2026-10-01 incident response). Reads evaluation.json's alert list
    and the normals file; changes no model or threshold."""
    alerts = {a["tx"]: a["label"] for a in ev["test_normals"]["combined_alerts"]}
    n = Counter()
    k = Counter()
    hours = Counter()
    for tx in iter_jsonl_gz(md.NORMALS):
        if str((tx.get("_meta") or {}).get("month")) < md.TEST_FIRST:
            continue
        g = "paused_failure" if paused_failure(tx) else "rest"
        n[g] += 1
        if g == "paused_failure":
            ts = int(tx["execution_outcome"]["block_timestamp"]) // 10**9
            hours[datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:00")] += 1
        lab = alerts.get(tx["transaction"]["hash"])
        if lab:
            k[(g, "medium+")] += 1
            k[(g, "high")] += lab == "high"
    out = {g: {lvl: rate(k[(g, lvl)], n[g]) for lvl in LEVELS} for g in n}
    for g in out:
        r = out[g]["medium+"]
        out[g]["alerts_per_day_medium+"] = {"est": r["rate"] * TXS_PER_DAY,
                                            "ci95": [x * TXS_PER_DAY for x in r["ci95"]]}
    out["paused_failure_hours"] = dict(hours.most_common())
    return out


# --- markdown tables ---------------------------------------------------------------------------------------------

def pct(r: dict, digits: int = 3) -> str:
    lo, hi = r["ci95"]
    return f"{r['k']}/{r['n']} = {100 * r['rate']:.{digits}f}% [{100 * lo:.{digits}f}, {100 * hi:.{digits}f}]"


def tables(ev: dict) -> str:
    L = [f"# NEAR Intents v1: evaluation tables\n",
         f"Generated by `near.intents.evaluate` from evaluation.json. Model `{ev['kind']}`, manifest sha256 "
         f"`{ev['manifest_sha256'][:16]}...`, scored {ev['scored_at']} (rescored {ev['rescored']} times). "
         f"Rates are k/n with Wilson 95% intervals in percent; alerts/day assume {ev['txs_per_day']:,} txs/day.\n",
         "Caveats: per-day figures pool the 2026-10-01 paused hour (see RESULTS.md 'Alerts per day'); the rules were "
         "developed on these campaigns and on the scouting seeds (RESULTS.md Limits 1 and 4).\n"]
    t = ev["test_normals"]
    L.append(f"## Sealed test normals (n={t['n']}, months {t['by_month']}, sources {t['by_source']})\n")
    L.append("| system | group | n | high | medium+ | high alerts/day | medium+ alerts/day |")
    L.append("|---|---|---|---|---|---|---|")
    for sys in SYSTEMS:
        for part in ("by_flow", "by_source", "failing_vs_ok"):
            for g, v in t[sys][part].items():
                if part != "by_flow" and g == "all":
                    continue
                a, b = v["alerts_per_day_high"], v["alerts_per_day_medium+"]
                L.append(f"| {sys} | {g} | {v['n']} | {pct(v['high_rate'])} | {pct(v['medium_plus_rate'])} | "
                         f"{a['est']:.0f} [{a['ci95'][0]:.0f}, {a['ci95'][1]:.0f}] | "
                         f"{b['est']:.0f} [{b['ci95'][0]:.0f}, {b['ci95'][1]:.0f}] |")
    L.append(f"\nRules fired on test normals: {t['rules_fired']}\n")
    L.append("Combined alerts on test normals:\n")
    for a in t["combined_alerts"]:
        L.append(f"- {a['label']} {a['flow']} failed={a['failed']} pct={a['pct']:.5f} rules={a['rules']} "
                 f"source={a['source']} `{a['tx']}`")
    L.append("\n## Campaign case studies (held out; never trained or calibrated on)\n")
    L.append("| campaign / role | n | combined high / medium / missed | combined medium+ | rules only medium+ "
             "| anomaly only medium+ | median anomaly pct |")
    L.append("|---|---|---|---|---|---|---|")
    for k, c in ev["cases"].items():
        cb = c["combined"]
        L.append(f"| {k} | {c['n']} | {cb['high']} / {cb['medium']} / {cb['missed']} | "
                 f"{pct(cb['medium_plus_rate'], 1)} | {pct(c['rules_only']['medium_plus_rate'], 1)} | "
                 f"{pct(c['anomaly_only']['medium_plus_rate'], 1)} | {c['anomaly_pct_median']:.4f} |")
    L.append("\nHigh-level detail per case (combined / rules only / anomaly only, high only):\n")
    for k, c in ev["cases"].items():
        L.append(f"- **{k}**: high {pct(c['combined']['high_rate'], 1)} / {pct(c['rules_only']['high_rate'], 1)} / "
                 f"{pct(c['anomaly_only']['high_rate'], 1)}; flows {c['by_flow']}; rules {c['rules_fired']}")
    L.append("\n## Development-period normals (train and calibration months; not sealed)\n")
    L.append("| slice | system | n | high | medium+ |")
    L.append("|---|---|---|---|---|")
    for part, d in ev["dev_normals"].items():
        for sys in SYSTEMS:
            v = d[sys]["all"]
            L.append(f"| {part} | {sys} | {v['n']} | {pct(v['high_rate'])} | {pct(v['medium_plus_rate'])} |")
        L.append(f"\n{part} rules fired: {d['rules_fired']}\n")
    L.append(f"\nscore_tx agreement with the batch path on labelled txs: {ev['score_tx_check']}\n")
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("stage", choices=["run", "tables", "paused"])
    ap.add_argument("--rescore", action="store_true")
    a = ap.parse_args(argv)
    if a.stage == "run":
        run(a.rescore)
    elif a.stage == "paused":
        out = paused(json.loads(EVAL_JSON.read_text()))
        (REPORTS / "paused_diagnostic.json").write_text(json.dumps(out, indent=1))
        print(json.dumps(out, indent=1))
    else:
        EVAL_MD.write_text(tables(json.loads(EVAL_JSON.read_text())))
        print(f"wrote {EVAL_MD}")


if __name__ == "__main__":
    main()
