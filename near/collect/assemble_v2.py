"""Assembly v2: train_v2 / train_v2_small / test_v1c from the v1 splits, the split-audit drop list, the blind relabel
batches (near/data/relabel/batch_*.jsonl) and the v2 fix commits (near/data/raw/fix_commits_v2_part*.jsonl).

Rules, in order:
1. v2 fix commits -> function rows exactly as v1 (near.collect.resolve.resolve_fix_commit + finalize: the parent
   version of each triaged changed fn is label 1, the commit version label 0, linked by pair_id). Groups mapped through
   the v1 copy-group merges. A row is dropped when its group (or repo group) is a test_v1 group, or it copies a test
   row (norm_hash; shape_hash of a long test real row; token 5-gram Jaccard >= 0.8; identifier-normalized Jaccard
   >= 0.8 with a long test label-1 / real row, the split-audit rules); its pair partner goes with it.
   Weight by triage confidence: high 1.0, medium 0.7.
2. train_v2 = train_v1 minus split_audit_v1_drop_ids `ids`, relabels applied (`apply_relabels`), plus the v2 rows;
   then the v1 rules: label conflicts (`assemble.resolve_conflicts`) and (norm_hash, label) dedupe.
3. test_v1c = test_v1 with the same relabels applied: rows removed or relabelled, none added.
4. train_v2_small (`assemble.small_train`), manifest with sha256s / counts / ids / removed ids, report.

    uv run python -m near.collect.assemble_v2 --resolve   # resolve the v2 fix commits (network/git), then assemble
    uv run python -m near.collect.assemble_v2             # assemble from the cached fix_commit_v2_samples.jsonl
"""
from __future__ import annotations

import argparse
import collections
import json
import statistics
from multiprocessing import Pool
from pathlib import Path

from near.collect import assemble as a1
from near.collect.assemble import REAL, tokens

DATA, RAW = a1.DATA, a1.RAW
RELABEL_DIR = DATA / "relabel"
FIX_V2_ROWS = DATA / "fix_commit_v2_samples.jsonl"
FIX_V2_LOG = RAW / "resolve_cache" / "resolve_log_v2.jsonl"
DROP_VERDICTS = ("wrong_function", "not_vulnerable", "fixed_code")
VERDICT_WEIGHT = {"confirmed": 1.0, "plausible": 0.6}
CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.7}
STRICT_JACCARD = 0.8  # split audit v1 near-copy threshold (raw and identifier-normalized)
# crates vendored from a test_v1 group: ref-farming/ is rozgo/ref-contracts' farming crate (split audit P1 copy rule)
VENDORED_TEST_PREFIXES = ("ref-farming/",)
KEYWORDS = {"as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false",
            "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
            "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while"}
TAXONOMY = {"non_private_callback", "unhandled_promise_result", "async_reentrancy", "missing_access_control",
            "missing_one_yocto", "signer_auth", "unguarded_upgrade", "unsafe_arithmetic", "precision_rounding",
            "storage_staking", "ft_receiver_trust", "unchecked_receiver", "gas_dos", "oracle_price", "logic_error"}


# ---------------------------------------------------------------- relabels
def load_relabels(paths: list[Path]) -> dict:
    """{id: relabel row} from the batch files; an id may appear once."""
    out = {}
    for p in paths:
        for line in p.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                assert r["id"] not in out, f"relabel id {r['id']} twice"
                assert r["verdict"] in VERDICT_WEIGHT or r["verdict"] in DROP_VERDICTS, r["verdict"]
                assert r["vuln_class_corrected"] in TAXONOMY | {None}, r["vuln_class_corrected"]
                out[r["id"]] = {**r, "batch": p.stem}
    return out


def apply_relabels(rows: list[dict], relabels: dict, split: str) -> tuple[list[dict], dict, collections.Counter]:
    """Relabel the real label-1 rows of one split. confirmed -> weight 1.0, plausible -> weight 0.6, both with the
    corrected vuln_class / severity (v1 values kept in *_v1 fields). wrong_function / not_vulnerable / fixed_code ->
    the row is removed (never turned into a negative) and its fixed pair with it. A kept positive whose pair_verdict is
    unchanged_or_partial loses its fixed pair (not a clean negative). Kept fixed pairs carry their positive's weight.
    Corpus / mutation_original copies of a real positive (`relabeled_from_real`) follow it: removed when every real
    positive with their norm_hash in this split is removed, else given its corrected vuln_class.
    Returns (rows, {removed id: reason}, stats)."""
    st = collections.Counter()
    by_id = {r["id"]: r for r in rows}
    removed, kept_pos, pair_of = {}, {}, {}
    for r in rows:
        rl = relabels.get(r["id"])
        if rl is None:
            continue
        assert rl["split"] == split, f"relabel {r['id']} is for {rl['split']}, row is in {split}"
        assert r["label"] == 1 and r["source"] in REAL, f"relabel {r['id']} is not a real label-1 row"
        st[f"verdict_{rl['verdict']}"] += 1
        partners = sorted({p for p in (r.get("pair_id"), rl.get("pair_id")) if p in by_id and by_id[p]["label"] == 0})
        if r.get("pair_id") and rl.get("pair_id") and r["pair_id"] != rl["pair_id"]:
            st["pair_id_mismatch_row_vs_relabel"] += 1
        if rl["verdict"] in DROP_VERDICTS:
            removed[r["id"]] = f"relabel_{rl['verdict']}"
            for p in partners:
                removed.setdefault(p, "pair_of_removed_positive")
            continue
        kept_pos[r["id"]] = rl
        for p in partners:
            if rl["pair_verdict"] == "unchanged_or_partial":
                removed.setdefault(p, "pair_unchanged_or_partial")
            else:
                pair_of[p] = (r["id"], rl)
    st["relabel_ids_not_in_split"] = sum(1 for i, rl in relabels.items() if rl["split"] == split and i not in by_id)

    # copies of real positives (v1 resolve_conflicts) follow the real rows with their norm_hash
    real_pos = collections.defaultdict(list)
    for r in rows:
        if r["source"] in REAL and r["label"] == 1:
            real_pos[r["norm_hash"]].append(r["id"])
    out = []
    for r in rows:
        if r["id"] in removed:
            continue
        if r["id"] in kept_pos:
            rl = kept_pos[r["id"]]
            r = {**r, "vuln_class_v1": r["vuln_class"], "severity_v1": r.get("severity"), "weight_v1": r.get("weight"),
                 "vuln_class": rl["vuln_class_corrected"] or r["vuln_class"],
                 "severity": rl["severity_corrected"] or r.get("severity"), "weight": VERDICT_WEIGHT[rl["verdict"]],
                 "relabel_verdict": rl["verdict"], "relabel_pair_verdict": rl["pair_verdict"],
                 "relabel_note": rl.get("note"), "relabel_batch": rl["batch"]}
            st["vuln_class_corrected"] += r["vuln_class"] != r["vuln_class_v1"]
            st["severity_corrected"] += r["severity"] != r["severity_v1"]
        elif r["id"] in pair_of:
            pid, rl = pair_of[r["id"]]
            r = {**r, "severity_v1": r.get("severity"), "weight_v1": r.get("weight"),
                 "severity": rl["severity_corrected"] or r.get("severity"), "weight": VERDICT_WEIGHT[rl["verdict"]],
                 "relabel_pair_verdict": rl["pair_verdict"]}
            st["pair_kept"] += 1
        elif r.get("relabeled_from_real") and r["label"] == 1:
            alive = [i for i in real_pos.get(r["norm_hash"], ()) if i not in removed]
            if not alive and any(i in removed for i in real_pos.get(r["norm_hash"], ())):
                removed[r["id"]] = "copy_of_removed_positive"
                continue
            if alive:
                src = by_id[alive[0]]
                rl = kept_pos.get(src["id"])
                if rl and rl["vuln_class_corrected"]:
                    r = {**r, "vuln_class_v1": r["vuln_class"], "vuln_class": rl["vuln_class_corrected"]}
                    st["copy_vuln_class_corrected"] += 1
            else:
                st["copy_without_real_row_in_split"] += 1
        out.append(r)
    st.update(collections.Counter(f"removed_{v}" for v in removed.values()))
    return out, removed, st


# ---------------------------------------------------------------- v2 fix commits
def resolve_fix_commits_v2(paths: list[Path]) -> tuple[list[dict], dict]:
    """Resolve the triaged v2 fix commits exactly as v1 (resolve.resolve_fix_commit, resolve.finalize); writes the rows
    to FIX_V2_ROWS and per-commit statuses to FIX_V2_LOG."""
    from near.collect import resolve as rs
    items = [json.loads(x) for p in paths for x in p.read_text().splitlines() if x.strip()]
    code = rs.Code()
    res = rs.run_all(code, items, rs.resolve_fix_commit, lambda c: c["repo"].lower())
    rows = []
    for it, (rs_, _, _) in res:
        for r in rs_:
            rows.append({**r, "triage": it.get("triage"), "triage_rank": it.get("triage_rank"),
                         "fix_commit": it["commit"]})
    final, log = rs.finalize(rows)
    FIX_V2_ROWS.write_text("".join(json.dumps(r) + "\n" for r in final))
    with FIX_V2_LOG.open("w") as fh:
        for it, (rs_, st, fst) in res:
            fh.write(json.dumps({"status": st, "fix_status": fst, "rows": len(rs_), "triage": it.get("triage"),
                                 "repo": it["repo"], "commit": it["commit"], "fns": it["fns"]}) + "\n")
    status = collections.Counter(st for _, (_, st, _) in res)
    fstatus = collections.Counter(fst for _, (rs_, _, fst) in res if rs_)
    return final, {"commits": len(items), "status": dict(status), "fix_status": dict(fstatus), "finalize": log}


def idnorm_tokens(code: str) -> list[str]:
    """Tokens with non-keyword identifiers -> ID, numbers -> N, strings -> S (split audit's identifier-normalized)."""
    out = []
    for t, s in tokens(code):
        if t in a1.STRINGS:
            out.append("S")
        elif t in a1.NUMBERS:
            out.append("N")
        elif t in a1.IDENTIFIERS and s not in KEYWORDS:
            out.append("ID")
        else:
            out.append(s)
    return out


def shingle_set(toks: list[str], k: int = a1.SHINGLE) -> frozenset:
    return frozenset(" ".join(toks[i:i + k]) for i in range(max(1, len(toks) - k + 1)))


def raw_tokens(code: str) -> list[str]:
    return ["S" if t in a1.STRINGS else s for t, s in tokens(code)]


def _set_jaccard(a: frozenset, b: frozenset) -> float:
    return len(a & b) / len(a | b) if a or b else 1.0


def _max_jaccard(s: frozenset, others: list[frozenset]) -> float:
    best = 0.0
    for o in others:
        if min(len(s), len(o)) >= best * max(len(s), len(o)):  # Jaccard <= min/max size
            best = max(best, _set_jaccard(s, o))
    return best


def screen_fix_commit_v2_rows(new: list[dict], test: list[dict], copy_map: dict, leak_norm: set = frozenset(),
                    vendored: tuple = VENDORED_TEST_PREFIXES) -> tuple[list[dict], dict, dict]:
    """Map v2 rows' groups through the v1 copy-group merges, then drop rows of a test group, rows under a crate vendored
    from a test group (`vendored` path prefixes), rows identical (norm_hash) to a train row the split audit dropped as a
    test copy (`leak_norm`), and rows that copy test code (norm_hash, long-real shape_hash, raw 5-gram Jaccard >= 0.8
    with any test row, identifier-normalized Jaccard >= 0.8 with a test label-1/real row of >= 60 tokens); a dropped
    row's pair partner goes too.
    Returns (kept, {id: reason}, {id: (max raw J, max idnorm J)})."""
    test_groups = {r["group"] for r in test} | {r["repo_group"] for r in test if r.get("repo_group")}
    norm = {r["norm_hash"] for r in test}
    shape = a1.shape_targets(test)
    raw_te = [shingle_set(raw_tokens(r["code"])) for r in test]
    idn_te = [shingle_set(idnorm_tokens(r["code"])) for r in test
              if (r["label"] == 1 or r["source"] in REAL) and r["n_tokens"] >= a1.SHAPE_MIN_TOKENS]
    removed, sim, out = {}, {}, []
    for r in new:
        r = dict(r)
        if r["group"] in copy_map:
            r["repo_group"], r["group"] = r["group"], copy_map[r["group"]]
        j_raw = _max_jaccard(shingle_set(raw_tokens(r["code"])), raw_te)
        j_idn = _max_jaccard(shingle_set(idnorm_tokens(r["code"])), idn_te)
        sim[r["id"]] = (round(j_raw, 3), round(j_idn, 3))
        if r["group"] in test_groups or r.get("repo_group") in test_groups:
            removed[r["id"]] = "test_group"
        elif (r.get("path") or "").startswith(vendored):
            removed[r["id"]] = "vendored_test_crate"
        elif r["norm_hash"] in leak_norm:
            removed[r["id"]] = "same_as_split_audit_drop"
        elif r["norm_hash"] in norm:
            removed[r["id"]] = "norm_hash"
        elif r["shape_hash"] in shape:
            removed[r["id"]] = "shape_hash"
        elif j_raw >= STRICT_JACCARD:
            removed[r["id"]] = "jaccard_0.8"
        elif j_idn >= STRICT_JACCARD:
            removed[r["id"]] = "idnorm_jaccard_0.8"
        out.append(r)
    for r in out:
        if r["id"] not in removed and r.get("pair_id") in removed:
            removed[r["id"]] = "pair_partner_removed"
    return [r for r in out if r["id"] not in removed], removed, sim


def weigh_fix_commit_v2_rows(rows: list[dict]) -> list[dict]:
    """Weight of a v2 fix-commit row (both sides of a pair) by triage confidence; severity weight kept aside."""
    return [{**r, "weight_severity": r.get("weight"), "weight": CONFIDENCE_WEIGHT.get(r.get("confidence"), 0.7)}
            for r in rows]


# ---------------------------------------------------------------- pipeline
def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _sig_worker(code: str) -> dict:
    s = a1.signatures(code)
    return {k: s[k] for k in ("norm_hash", "shape_hash", "n_tokens")}


def _counts(rows: list[dict]) -> collections.Counter:
    return collections.Counter((r["source"], r["label"]) for r in rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--resolve", action="store_true", help="resolve the v2 fix commits again (git / GitHub)")
    args = ap.parse_args()
    fix_paths = sorted(RAW.glob("fix_commits_v2_part*.jsonl"))
    if args.resolve or not FIX_V2_ROWS.exists():
        new, resolve_info = resolve_fix_commits_v2(fix_paths)
    else:
        new = _load(FIX_V2_ROWS)
        resolve_info = None
    if resolve_info is None:
        log = _load(FIX_V2_LOG)
        resolve_info = {"commits": len(log), "status": dict(collections.Counter(x["status"] for x in log)),
                        "fix_status": dict(collections.Counter(x["fix_status"] for x in log if x["rows"])),
                        "finalize": "cached"}
    n_new_resolved = len(new)

    train1, test1 = _load(DATA / "train_v1.jsonl"), _load(DATA / "test_v1.jsonl")
    drop = json.loads((DATA / "split_audit_v1_drop_ids.json").read_text())
    assert drop["train_sha256"] == a1._sha256(DATA / "train_v1.jsonl"), "drop list was made for another train_v1"
    assert drop["test_sha256"] == a1._sha256(DATA / "test_v1.jsonl"), "drop list was made for another test_v1"
    v1_manifest = json.loads((DATA / "split_manifest_v1.json").read_text())
    copy_map = v1_manifest["split"]["copy_groups"]
    relabel_paths = sorted(RELABEL_DIR.glob("batch_*.jsonl"))
    relabels = load_relabels(relabel_paths)

    drop_ids = set(drop["ids"])
    train = [r for r in train1 if r["id"] not in drop_ids]
    n_audit_dropped = len(train1) - len(train)
    relabel_pos_in_drop = sorted(i for i in drop_ids if i in relabels)
    train, removed_train, st_train = apply_relabels(train, relabels, "train")
    test, removed_test, st_test = apply_relabels(test1, relabels, "test")

    with Pool(17) as pool:
        sigs = pool.map(_sig_worker, [r["code"] for r in new], chunksize=8)
    for r, s in zip(new, sigs):
        r.update(s)
    leak_norm = {r["norm_hash"] for r in train1 if r["id"] in drop_ids}
    new, removed_new, sim = screen_fix_commit_v2_rows(new, test1, copy_map, leak_norm)
    new = weigh_fix_commit_v2_rows(new)
    n_new_screened = len(new)

    rows = train + new
    rows, conflicts = a1.resolve_conflicts(rows)
    labels = collections.defaultdict(set)
    for r in rows:
        labels[r["norm_hash"]].add(r["label"])
    assert not [h for h, v in labels.items() if len(v) > 1], "label conflict left after resolve_conflicts"
    n_new_after_conflicts = sum(1 for r in rows if "triage" in r)
    train, n_dedupe = a1.dedupe(rows)
    new_kept = [r for r in train if "triage" in r]  # v2 rows carry `triage`; a v1 duplicate of one wins the dedupe
    removed_pos = {r["norm_hash"]: r for r in train1 if removed_train.get(r["id"], "").startswith("relabel_")}
    revived = [(r, removed_pos[r["norm_hash"]]) for r in new_kept if r["label"] == 1 and r["norm_hash"] in removed_pos]

    # checks (asserted)
    ids_tr, ids_te = {r["id"] for r in train}, {r["id"] for r in test}
    assert len(ids_tr) == len(train) and len(ids_te) == len(test), "duplicate id within a split"
    assert not ids_tr & ids_te, "id shared between train and test"
    assert not {r["group"] for r in train} & {r["group"] for r in test}, "group shared between train and test"
    te_groups_all = {r["group"] for r in test1} | {r["repo_group"] for r in test1 if r.get("repo_group")}
    assert not {r["group"] for r in new_kept} & te_groups_all, "v2 fix-commit row in a test_v1 group"
    assert not {r["norm_hash"] for r in train} & {r["norm_hash"] for r in test1}, "norm_hash shared with test_v1"
    assert not {r["shape_hash"] for r in train} & a1.shape_targets(test1), "shape_hash of a test real row in train"
    assert ids_te <= {r["id"] for r in test1}, "test_v1c holds a row not in test_v1"
    assert not drop_ids & ids_tr, "split-audit drop id left in train"
    for split_rows in (train, test):
        lab = collections.defaultdict(set)
        for r in split_rows:
            lab[r["norm_hash"]].add(r["label"])
        assert not [h for h, v in lab.items() if len(v) > 1], "norm_hash with two labels"

    small, cap = a1.small_train(train)
    out = {"train_v2.jsonl": train, "test_v1c.jsonl": test, "train_v2_small.jsonl": small}
    for name, rs_ in out.items():
        a1._write(DATA / name, rs_)
    counts = collections.Counter()
    for split, rs_ in out.items():
        for r in rs_:
            counts["|".join(map(str, (split.removesuffix(".jsonl"),) + a1._key(r)))] += 1
    inputs = ["train_v1.jsonl", "test_v1.jsonl", "split_audit_v1_drop_ids.json", "split_manifest_v1.json",
              FIX_V2_ROWS.name] + [str(p.relative_to(DATA)) for p in relabel_paths + fix_paths]
    manifest = {
        "seed": a1.SEED,
        "rules": {"relabel_drop_verdicts": list(DROP_VERDICTS), "relabel_weight": VERDICT_WEIGHT,
                  "fix_commit_v2_confidence_weight": CONFIDENCE_WEIGHT, "strict_jaccard": STRICT_JACCARD,
                  "v1_jaccard_min": a1.JACCARD_MIN, "small_target": a1.SMALL_TARGET,
                  "small_corpus_cap_per_group": cap},
        "inputs": {p: a1._sha256(DATA / p) for p in inputs},
        "files": {name: {"sha256": a1._sha256(DATA / name), "rows": len(rs_)} for name, rs_ in out.items()},
        "checks": {"id_overlap": 0, "group_overlap": 0, "norm_hash_overlap_with_test_v1": 0,
                   "long_real_shape_hash_overlap": 0, "asserted": True},
        "groups": {"test": sorted({r["group"] for r in test}), "train": sorted({r["group"] for r in train})},
        "counts": dict(sorted(counts.items())),
        "removed": {"train_split_audit": sorted(drop_ids), "train_relabel": dict(sorted(removed_train.items())),
                    "test_relabel": dict(sorted(removed_test.items())),
                    "fix_commit_v2_screen": dict(sorted(removed_new.items()))},
        "ids": {"test": sorted(ids_te), "train": sorted(ids_tr), "train_small": sorted(r["id"] for r in small),
                "train_fix_commit_v2": sorted(r["id"] for r in new_kept)},
    }
    (DATA / "split_manifest_v2.json").write_text(json.dumps(manifest, indent=1) + "\n")
    ctx = dict(train1=train1, test1=test1, relabels=relabels, st_train=st_train, st_test=st_test,
               removed_train=removed_train, removed_test=removed_test, removed_new=removed_new, sim=sim,
               n_audit_dropped=n_audit_dropped, relabel_pos_in_drop=relabel_pos_in_drop, resolve_info=resolve_info,
               n_new_resolved=n_new_resolved, n_new_screened=n_new_screened, new_kept=new_kept,
               conflicts=conflicts, n_dedupe=n_dedupe, revived=revived,
               n_new_after_conflicts=n_new_after_conflicts, cap=cap, out=out, manifest=manifest,
               new_all=_load(FIX_V2_ROWS))
    report = write_report(ctx)
    (DATA / "assembly_v2_report.md").write_text(report)
    print(report)


# ---------------------------------------------------------------- report
def _table(header: list[str], rows: list[list]) -> list[str]:
    return ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)] + \
        ["| " + " | ".join(str(x) for x in r) + " |" for r in rows]


def _pct(k: int, n: int) -> str:
    if not n:
        return "-"
    from near.model.eval_common import wilson
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {k / n:.0%} [{lo:.0%}, {hi:.0%}]"


def write_report(c: dict) -> str:
    out, man, rl = c["out"], c["manifest"], c["relabels"]
    train, test, small = out["train_v2.jsonl"], out["test_v1c.jsonl"], out["train_v2_small.jsonl"]
    v1_rows = {r["id"]: r for r in c["train1"] + c["test1"]}
    L = ["# Assembly v2 report (train_v2 / train_v2_small / test_v1c)", "",
         "Built by `uv run python -m near.collect.assemble_v2` from train_v1 / test_v1, "
         "`split_audit_v1_drop_ids.json`, the relabel batches `near/data/relabel/batch_*.jsonl` "
         f"({len(rl)} rows) and the v2 fix commits `near/data/raw/fix_commits_v2_part*.jsonl` "
         f"({c['resolve_info']['commits']} commits). test_v1c labels were reviewed blind to model predictions.", "",
         "## Output", ""]
    L += _table(["file", "rows", "sha256"], [[n, v["rows"], f"`{v['sha256']}`"] for n, v in man["files"].items()])
    L += ["", "Checks (asserted): no shared id or group between train_v2 and test_v1c; no train_v2 norm_hash in "
          "test_v1 (so none in test_v1c); no train_v2 row with the shape_hash of a long test_v1 real row; no v2 "
          "fix-commit row in a test_v1 group or repo group; no split-audit drop id in train_v2; test_v1c ids are a "
          "subset of test_v1; no norm_hash with two labels within a split.", ""]

    # ---- rules applied
    L += ["## Rules applied and rows touched", ""]
    rows = [["train_v1 rows", len(c["train1"])],
            ["split-audit drop ids removed from train (leak fix)", c["n_audit_dropped"]],
            ["  of which real label-1 rows that also have a relabel", len(c["relabel_pos_in_drop"])]]
    for k, v in sorted(c["st_train"].items()):
        rows.append([f"train relabel: {k}", v])
    for k, v in sorted(c["st_test"].items()):
        rows.append([f"test relabel: {k}", v])
    rows += [["v2 fix-commit rows resolved (label 1 + label 0)", c["n_new_resolved"]]]
    for k, v in sorted(collections.Counter(c["removed_new"].values()).items()):
        rows.append([f"v2 fix-commit rows removed by the test screen: {k}", v])
    rows += [["v2 fix-commit rows after the screen", c["n_new_screened"]]]
    for k, v in sorted(c["conflicts"].items()):
        rows.append([f"v1 conflict rule (train_v2 incl. v2 rows): {k}", v])
    rows += [["(norm_hash, label) duplicates dropped in train_v2", c["n_dedupe"]],
             ["v2 fix-commit rows in train_v2", len(c["new_kept"])]]
    L += _table(["rule", "rows"], rows)
    L += ["", "Relabel rules: confirmed -> label 1, weight 1.0; plausible -> label 1, weight 0.6; wrong_function / "
          "not_vulnerable / fixed_code -> the positive is removed (not turned into a negative) and its fixed pair with "
          "it; a kept positive with pair_verdict unchanged_or_partial loses its fixed pair; vuln_class_corrected and "
          "severity_corrected applied (v1 values in `vuln_class_v1`, `severity_v1`, `weight_v1`); kept fixed pairs "
          "carry their positive's weight; corpus / mutation_original rows labelled 1 in v1 as copies of a real "
          "positive are removed when that positive is removed. Rows keep their v1 `pair_id`; a partner that was "
          "removed simply no longer exists (the protocol's pair_rank skips it).", ""]

    # ---- relabel agreement
    L += ["## Relabel agreement with the v1 labels", "",
          "Share of v1 real label-1 rows the reviewer kept as vulnerable (confirmed or plausible), Wilson 95% CI. "
          "`confirmed` alone in the second column.", ""]

    def agree(sel):
        n = len(sel)
        k = sum(rl[i]["verdict"] in VERDICT_WEIGHT for i in sel)
        kc = sum(rl[i]["verdict"] == "confirmed" for i in sel)
        return [n, _pct(k, n), _pct(kc, n)]

    def by(keyf, title):
        g = collections.defaultdict(list)
        for i in rl:
            if i in v1_rows:
                g[keyf(i)].append(i)
        return _table([title, "rows", "kept (confirmed+plausible)", "confirmed"],
                      [[k] + agree(v) for k, v in sorted(g.items(), key=lambda kv: str(kv[0]))])

    L += by(lambda i: rl[i]["split"], "split") + [""]
    L += by(lambda i: (rl[i]["split"], v1_rows[i]["source"]), "split, source") + [""]
    L += by(lambda i: v1_rows[i].get("severity") or "-", "v1 severity") + [""]
    L += by(lambda i: v1_rows[i]["vuln_class"], "v1 vuln_class") + [""]
    L += by(lambda i: bool(v1_rows[i].get("code_from_snippet")), "code_from_snippet") + [""]
    vc = collections.Counter(rl[i]["verdict"] for i in rl)
    pv = collections.Counter(rl[i]["pair_verdict"] for i in rl)
    L += [f"Verdicts: {dict(vc.most_common())}. Pair verdicts: {dict(pv.most_common())}.", ""]
    trans = collections.Counter((v1_rows[i]["vuln_class"], rl[i]["vuln_class_corrected"]) for i in rl
                                if i in v1_rows and rl[i]["vuln_class_corrected"]
                                and rl[i]["vuln_class_corrected"] != v1_rows[i]["vuln_class"])
    n_kept = sum(1 for i in rl if rl[i]["verdict"] in VERDICT_WEIGHT)
    n_vc = sum(1 for i in rl if rl[i]["verdict"] in VERDICT_WEIGHT and rl[i]["vuln_class_corrected"]
               and rl[i]["vuln_class_corrected"] != v1_rows.get(i, {}).get("vuln_class"))
    L += [f"vuln_class agreement among kept positives: {n_kept - n_vc}/{n_kept} unchanged. Corrections (all verdicts) "
          "v1 -> corrected: " + ", ".join(f"{a} -> {b} ({n})" for (a, b), n in trans.most_common()) + ".", ""]
    sev = collections.Counter((v1_rows[i].get("severity"), rl[i]["severity_corrected"]) for i in rl
                              if i in v1_rows and rl[i]["severity_corrected"]
                              and rl[i]["severity_corrected"] != v1_rows[i].get("severity"))
    L += ["Severity corrections v1 -> corrected: " + ", ".join(f"{a} -> {b} ({n})" for (a, b), n in sev.most_common())
          + ".", ""]

    # ---- positives surviving
    L += ["## Real label-1 rows: v1 vs v2, by source", ""]

    def pos(rs_, src):
        return sum(1 for r in rs_ if r["label"] == 1 and r["source"] == src)

    tr1 = [r for r in c["train1"]]
    rows = []
    for s in REAL:
        rows.append([s, pos(tr1, s), pos(train, s), sum(1 for r in c["new_kept"] if r["source"] == s and r["label"]),
                     pos(c["test1"], s), pos(test, s)])
    rows.append(["**all real**", sum(r[1] for r in rows), sum(r[2] for r in rows), sum(r[3] for r in rows),
                 sum(r[4] for r in rows), sum(r[5] for r in rows)])
    L += _table(["source", "train_v1", "train_v2", "  of which v2 fix commits", "test_v1", "test_v1c"], rows)
    gp = lambda rs_: len({r["group"] for r in rs_ if r["label"] == 1 and r["source"] in REAL})
    L += ["", f"Groups holding a real label-1 row: train_v1 {gp(tr1)}, train_v2 {gp(train)}, test_v1 {gp(c['test1'])}, "
          f"test_v1c {gp(test)}. Groups in all: train_v2 {len({r['group'] for r in train})}, test_v1c "
          f"{len({r['group'] for r in test})}."]
    L += ["", "## Real label-1 rows by vuln_class", ""]
    cls = lambda rs_: collections.Counter(r["vuln_class"] for r in rs_ if r["label"] == 1 and r["source"] in REAL)
    a, b, n2, d, e = cls(tr1), cls(train), cls(c["new_kept"]), cls(c["test1"]), cls(test)
    L += _table(["vuln_class", "train_v1", "train_v2", "  v2 fix commits", "test_v1", "test_v1c"],
                [[k, a[k], b[k], n2[k], d[k], e[k]] for k in sorted(set(a) | set(b) | set(d) | set(e), key=str)])
    L += ["", "## Real label-1 rows by source x vuln_class (train_v2 / test_v1c)", ""]
    sc = lambda rs_: collections.Counter((r["source"], r["vuln_class"]) for r in rs_
                                         if r["label"] == 1 and r["source"] in REAL)
    x, y = sc(train), sc(test)
    L += _table(["source", "vuln_class", "train_v2", "test_v1c"], [[k[0], k[1], x[k], y[k]] for k in sorted(set(x) | set(y), key=str)])
    L += ["", "## Weights and pairs of the real rows", ""]
    for name, rs_ in (("train_v2", train), ("test_v1c", test)):
        w = collections.Counter((r["source"], r["label"], r.get("weight"), r.get("relabel_verdict") or "-")
                                for r in rs_ if r["source"] in REAL)
        L.append(f"- **{name}** (source, label, weight, verdict): "
                 + ", ".join(f"{k}: {v}" for k, v in sorted(w.items(), key=str)))
        ids = {r["id"] for r in rs_}
        n_pairs = sum(1 for r in rs_ if r["source"] in REAL and r["label"] == 1 and r.get("pair_id") in ids)
        dangling = sum(1 for r in rs_ if r.get("pair_id") and r["pair_id"] not in ids)
        info = sum(1 for r in rs_ if r["source"] in REAL and r["label"] == 1 and r.get("severity") == "info")
        L.append(f"  real (vulnerable, fixed) pairs present: {n_pairs}; rows whose pair_id partner is absent: "
                 f"{dangling}; real label-1 rows still severity info: {info}.")
    L += [""]

    # ---- counts
    L += ["## Counts: split x source x label", ""]
    cnt = {n: _counts(rs_) for n, rs_ in [("train_v1", c["train1"]), ("test_v1", c["test1"])] + list(out.items())}
    keys = sorted(set().union(*cnt.values()), key=lambda k: (a1.SOURCE_RANK[k[0]], k[1]))
    names = ["train_v1", "train_v2.jsonl", "train_v2_small.jsonl", "test_v1", "test_v1c.jsonl"]
    L += _table(["source", "label"] + [n.removesuffix(".jsonl") for n in names],
                [[k[0], k[1]] + [cnt[n][k] for n in names] for k in keys] +
                [["**all**", ""] + [sum(cnt[n].values()) for n in names]])
    L += ["", f"train_v2_small: every label-1, mutation, mutation_original and real fixed row of train_v2, plus corpus "
          f"negatives capped at {c['cap']} per group (seeded) to reach {a1.SMALL_TARGET}: {len(small)} rows.", ""]

    # ---- v2 fix commits
    ri = c["resolve_info"]
    L += ["## v2 fix commits", "",
          f"Resolution (resolve.resolve_fix_commit, as v1): {ri['commits']} commits; status {ri['status']}; fixed side "
          f"{ri['fix_status']}; finalize {ri['finalize']}. Per-commit log: "
          f"`near/data/raw/resolve_cache/{FIX_V2_LOG.name}`; rows: `near/data/{FIX_V2_ROWS.name}`.", ""]
    nk = c["new_kept"]
    by_conf = collections.Counter((r.get("confidence"), r["label"]) for r in nk)
    years = collections.Counter((r.get("date") or "-")[:4] for r in nk if r["label"] == 1)
    L += [f"In train_v2: {sum(r['label'] for r in nk)} label 1, {sum(1 - r['label'] for r in nk)} label 0, "
          f"{len({r['group'] for r in nk})} groups ({len({r['group'] for r in nk} - {r['group'] for r in c['train1']})} "
          f"not in train_v1). By (confidence, label): {dict(sorted(by_conf.items(), key=str))}. Label-1 rows by year: "
          f"{dict(sorted(years.items()))}.", ""]
    rem = collections.Counter(c["removed_new"].values())
    allnew = {r["id"]: r for r in c["new_all"]}
    L += [f"Screen against test_v1 removed {sum(rem.values())} rows: {dict(rem)}. Removed rows: "
          + (", ".join(f"`{allnew[i]['repo'].removeprefix('https://github.com/')}` {allnew[i]['fn']} "
                       f"(label {allnew[i]['label']}, {why}, J raw/idnorm {c['sim'][i]})"
                       for i, why in sorted(c["removed_new"].items(), key=lambda kv: (kv[1], kv[0]))) or "none") + ".", ""]
    close = sorted(((v, i) for i, v in c["sim"].items() if i not in c["removed_new"] and max(v) >= 0.5), reverse=True)
    L += ["Kept v2 rows with a max Jaccard to a test_v1 row of >= 0.5 (raw or identifier-normalized; below the 0.8 "
          "drop threshold): " + (", ".join(f"`{allnew[i]['repo'].removeprefix('https://github.com/')}` {allnew[i]['fn']} "
                                           f"{v}" for v, i in close) or "none") + ".", ""]
    L += [f"v2 rows dropped by the conflict rule (fixed code identical to a real vulnerable row): "
          f"{c['n_new_screened'] - c['n_new_after_conflicts']}; by the (norm_hash, label) dedupe (a v1 real row of the "
          f"same code and label wins; a v2 row wins over a v1 mutant / corpus copy): "
          f"{c['n_new_after_conflicts'] - len(nk)}. v2 label-1 rows identical to a v1 "
          "positive the relabel removed (kept: the fix commit is separate evidence that the code was changed for "
          "security): " + (", ".join(f"`{r['repo'].removeprefix('https://github.com/')}` {r['fn']} (v1 {o['source']}, "
                                    f"{c['removed_train'][o['id']]})" for r, o in c["revived"]) or "none") + ".", ""]
    jump = [r for r in nk if "jump" in r["group"]]
    L += [f"Flagged by triage: hack-a-chain-software/jump.project (possible copy of test group "
          f"blockapex/jump-defi-contracts) contributes {len(jump)} rows to train_v2, max Jaccard to any test row "
          f"{max((max(c['sim'][r['id']]) for r in jump), default=0)}.", ""]

    L += ["## Function length (lines) of real rows", ""]
    rows = []
    for name, rs_ in (("train_v2", train), ("test_v1c", test)):
        for s in REAL:
            for lab in (1, 0):
                xs = [len(r["code"].splitlines()) for r in rs_ if r["source"] == s and r["label"] == lab]
                if xs:
                    rows.append([name, s, lab, len(xs), statistics.median(xs)])
    L += _table(["split", "source", "label", "rows", "median lines"], rows)
    L += ["", "## Limits", "",
          "- Relabels are one reviewer's reading of each function against the finding text; `plausible` rows are "
          "kept at weight 0.6 rather than dropped, so some noise remains.",
          "- Removing not_vulnerable / wrong_function positives shrinks the real positive set; train_v2 real "
          "positives are fewer but cleaner. test_v1c is not comparable number-for-number with test_v1.",
          "- About half of the v2 fix commits are 2026 hackathon / testnet code with self- or AI-review fixes; "
          "they are weighted by triage confidence only.",
          "- Mixed commits label every triaged fn the commit changed; function-level labels there are less precise.",
          "- The leak screen compares code text; an edited copy of a test project below 0.8 Jaccard can remain.", ""]
    return "\n".join(L)


if __name__ == "__main__":
    main()
