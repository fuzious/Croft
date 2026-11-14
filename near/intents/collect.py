"""Bulk collection of NEAR Intents (intents.near) transactions from FastNEAR.

    python -m near.intents.collect labelled   # the scouting's labelled txs, full receipts -> labelled.jsonl.gz
    python -m near.intents.collect normals    # month-stratified sample of intents.near history -> normals.jsonl.gz
    python -m near.intents.collect stats      # counts by month, flow type, success/failure

The label file defaults to near/data/intents/all_labelled_txs.jsonl (from archives/near_intents.zip, unpacked at the
repo root) and the attacker list to near/intents/fixtures/attacker_accounts.json. --scout optionally names a scouting
directory whose bulk-access/data/*/txs.jsonl seed both pulls; without it, the labelled pull fetches every hash and a
fresh normals pull starts from FastNEAR pages only.

Records are FastNEAR transaction JSON exactly as returned plus a top-level "_meta". Files are gzip JSONL written one
gzip member per page, so a killed run loses at most the page being written; `repair_jsonl_gz` trims a partial tail.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import collections
import datetime as dt
import gzip
import json
import os
import random
import re
import signal
import sys
import time
import zlib
from pathlib import Path
from typing import Iterable, Iterator

from near.intents.fastnear import FastNear, Refused, dedupe_txs, tx_hash, unique

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "near" / "data" / "intents"
LABELS = DATA / "all_labelled_txs.jsonl"
ATTACKERS = ROOT / "near" / "intents" / "fixtures" / "attacker_accounts.json"
INTENTS = "intents.near"
POSITIVE_ROLES = {"exploit", "attempt"}
NEGATIVE_ROLES = {"team_regression_test"}
CLUSTER_ROLES = {"setup", "cashout", "setup_funding_via_intents"}
# Signers of labelled rows that also sign ordinary intents.near traffic: the contract itself and relayers.
INFRASTRUCTURE = {INTENTS, "meteor-relayer.near", "team.herewallet.near"}
DEPOSIT_METHODS = {"ft_on_transfer", "mt_on_transfer", "nft_on_transfer"}
EXECUTE_METHODS = {"execute_intents", "simulate_intents"}
HEX64 = re.compile(r"\b[0-9a-f]{64}\b")
NAMED = re.compile(r"\b[a-z0-9][a-z0-9_\-]*(?:\.[a-z0-9_\-]+)*\.near\b")


# ---------- labels and meta ----------

def label_for_role(role: str):
    if role in POSITIVE_ROLES:
        return 1
    if role in NEGATIVE_ROLES:
        return 0
    if role in CLUSTER_ROLES:
        return "cluster"
    raise ValueError(f"unknown role {role!r}")


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def attach_meta(tx: dict, source: str, label, campaign: str | None = None, role: str | None = None,
                **extra) -> dict:
    meta = {"source": source, "fetched_at": now_iso(), "label": label, "campaign": campaign, "role": role}
    meta.update(extra)
    return {**{k: v for k, v in tx.items() if k != "_meta"}, "_meta": meta}


def labelled_meta(row: dict, source: str) -> dict:
    return {"source": source, "label": label_for_role(row["role"]), "campaign": row["incident"], "role": row["role"]}


# ---------- attacker exclusion ----------

def attacker_ids(doc: dict) -> set[str]:
    """Account ids (64-hex implicit or *.near) named in attacker_accounts.json, skipping keys marked not_attacker."""
    ids: set[str] = set()

    def walk(v):
        if isinstance(v, str):
            ids.update(HEX64.findall(v))
            ids.update(NAMED.findall(v))
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    for k, v in doc.items():
        if "not_attacker" not in k:
            walk(v)
    return ids - {INTENTS}


def load_labels(path: Path) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def labelled_signers(rows: Iterable[dict]) -> set[str]:
    """Signers of labelled rows outside NEGATIVE_ROLES (attackers and their setup and cashout accounts), minus
    INFRASTRUCTURE. Catches accounts such as campaign setup signers that attacker_accounts.json does not name."""
    return {r["signer"] for r in rows if r["role"] not in NEGATIVE_ROLES} - INFRASTRUCTURE


def _decoded_args(v, out: list[str]) -> None:
    if isinstance(v, dict):
        for k, x in v.items():
            if k == "args" and isinstance(x, str):
                try:
                    out.append(base64.b64decode(x, validate=True).decode("utf-8", "ignore"))
                except (binascii.Error, ValueError):
                    pass
            else:
                _decoded_args(x, out)
    elif isinstance(v, list):
        for x in v:
            _decoded_args(x, out)


def mentions_any(tx: dict, ids: set[str]) -> bool:
    """True if any id appears anywhere in the tx: accounts, logs, or base64-decoded function-call args."""
    parts = [json.dumps(tx)]
    _decoded_args(tx, parts)
    text = "\n".join(parts)
    return any(i in text for i in ids)


def exclusion_reason(tx: dict, attackers: set[str], signers: set[str]) -> str | None:
    """Why a candidate normal is dropped: signed by a labelled non-team signer, or mentions an attacker id."""
    if (tx.get("transaction") or {}).get("signer_id") in signers:
        return "labelled_signer"
    if mentions_any(tx, attackers):
        return "attacker"
    return None


# ---------- tx shape ----------

def tx_month(tx: dict) -> str:
    ts = int(tx["execution_outcome"]["block_timestamp"]) / 1e9
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m")


def tx_height(tx: dict) -> int:
    return int(tx["execution_outcome"]["block_height"])


def intents_methods(tx: dict) -> list[str]:
    """Function-call methods of every receipt executed on intents.near."""
    out = []
    for r in tx.get("receipts") or []:
        rr = r.get("receipt") or {}
        if rr.get("receiver_id") != INTENTS:
            continue
        body = rr.get("receipt") or {}
        for a in (body.get("Action") or {}).get("actions") or []:
            if isinstance(a, dict) and "FunctionCall" in a:
                out.append(a["FunctionCall"]["method_name"])
    return out


def flow_type(tx: dict) -> str:
    ms = set(intents_methods(tx))
    if ms & EXECUTE_METHODS:
        return "execute_intents"
    if ms & DEPOSIT_METHODS:
        return "deposit"
    if any(m.endswith("_withdraw") for m in ms):
        return "withdrawal"
    return "other"


def _is_failure(outcome: dict) -> bool:
    return "Failure" in ((outcome or {}).get("outcome") or {}).get("status", {})


def any_receipt_failed(tx: dict) -> bool:
    return _is_failure(tx.get("execution_outcome")) or any(
        _is_failure(r.get("execution_outcome")) for r in tx.get("receipts") or [])


# ---------- month windows ----------

def month_starts(first: str, last: str) -> list[str]:
    y, m = map(int, first.split("-"))
    out = []
    while f"{y:04d}-{m:02d}" <= last:
        out.append(f"{y:04d}-{m:02d}")
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


def _month_ts_ns(month: str) -> int:
    y, m = map(int, month.split("-"))
    return int(dt.datetime(y, m, 1, tzinfo=dt.timezone.utc).timestamp()) * 10**9


def _height_at(probes: list[tuple[int, int]], ts_ns: int) -> int:
    for (h0, t0), (h1, t1) in zip(probes, probes[1:]):
        if t0 <= ts_ns <= t1:
            return h0 + ((ts_ns - t0) * (h1 - h0)) // max(1, t1 - t0)
    raise ValueError("timestamp outside probe range")


def month_windows(probes: list[tuple[int, int]], first_height: int, last_height: int) -> list[dict]:
    """Monthly block-height windows from (height, timestamp_ns) probes, by linear interpolation between probes."""
    probes = sorted(set(probes))
    months = month_starts(dt.datetime.fromtimestamp(probes[0][1] / 1e9, dt.timezone.utc).strftime("%Y-%m"),
                          dt.datetime.fromtimestamp(probes[-1][1] / 1e9, dt.timezone.utc).strftime("%Y-%m"))
    starts = [first_height] + [_height_at(probes, _month_ts_ns(m)) for m in months[1:]]
    ends = [s - 1 for s in starts[1:]] + [last_height]
    return [{"window": m, "from_height": s, "to_height": e} for m, s, e in zip(months, starts, ends)]


def page_hashes(rows: list[dict], known: set[str], k: int, rng: random.Random) -> list[str]:
    hs = [h for h in unique(r["transaction_hash"] for r in rows) if h not in known]
    return rng.sample(hs, k) if len(hs) > k else hs


# ---------- gzip JSONL store ----------

def _complete_members(path: Path) -> Iterator[tuple[int, bytes]]:
    """Yield (end_offset, decompressed bytes) for each complete gzip member; stop at a partial tail."""
    with open(path, "rb") as f:
        d, buf, pos, pending = zlib.decompressobj(31), [], 0, b""
        while True:
            chunk = pending or f.read(1 << 20)
            pending = b""
            if not chunk:
                return
            try:
                buf.append(d.decompress(chunk))
            except zlib.error:
                return
            if d.eof:
                end = pos + len(chunk) - len(d.unused_data)
                yield end, b"".join(buf)
                d, buf, pos, pending = zlib.decompressobj(31), [], end, d.unused_data
            else:
                pos += len(chunk)


def iter_jsonl_gz(path: Path) -> Iterator[dict]:
    path = Path(path)
    if not path.exists():
        return
    for _, data in _complete_members(path):
        for line in data.decode("utf-8").splitlines():
            if line.strip():
                yield json.loads(line)


def load_jsonl_gz(path: Path) -> list[dict]:
    return list(iter_jsonl_gz(path))


def repair_jsonl_gz(path: Path) -> int:
    """Truncate a partial trailing gzip member left by a killed writer. Returns the resulting size."""
    path = Path(path)
    if not path.exists():
        return 0
    good = 0
    for good, _ in _complete_members(path):
        pass
    if good != path.stat().st_size:
        with open(path, "r+b") as f:
            f.truncate(good)
    return good


def append_jsonl_gz(path: Path, rows: Iterable[dict]) -> None:
    data = "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows)
    if data:
        with open(path, "ab") as f:
            f.write(gzip.compress(data.encode("utf-8")))
            f.flush()
            os.fsync(f.fileno())


# ---------- seeds ----------

def seed_txs(scout: Path | None, skip_dirs: tuple[str, ...] = ()) -> Iterator[tuple[str, dict]]:
    """(directory name, tx) per line of scout/bulk-access/data/*/txs.jsonl; nothing if scout is None or absent."""
    if scout is None:
        return
    base = scout / "bulk-access" / "data"
    for p in sorted(base.glob("*/txs.jsonl")):
        if p.parent.name in skip_dirs:
            continue
        with open(p) as f:
            for line in f:
                if line.strip():
                    t = json.loads(line)
                    if t:
                        yield p.parent.name, t


class Logger:
    def __init__(self, path: Path):
        self.path = path

    def __call__(self, msg: str) -> None:
        line = f"{now_iso()} {msg}"
        print(line, flush=True)
        with open(self.path, "a") as f:
            f.write(line + "\n")


# ---------- subcommands ----------

def cmd_labelled(a) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    log = Logger(DATA / "collect.log")
    rows = load_labels(a.labels)
    by_hash = {r["tx_hash"]: r for r in rows}
    found: dict[str, tuple[str, dict]] = {}
    for d, t in seed_txs(a.scout):
        h = tx_hash(t)
        if h in by_hash and h not in found:
            found[h] = (f"fastnear-seed:{d}", t)
    missing = [h for h in by_hash if h not in found]
    log(f"labelled: {len(by_hash)} hashes, {len(found)} from seeds, fetching {len(missing)}")
    fn = FastNear(log=log)
    for t in fn.transactions(missing):
        if tx_hash(t) in by_hash:
            found[tx_hash(t)] = ("fastnear", t)
    out = DATA / "labelled.jsonl.gz"
    tmp = out.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    recs = [attach_meta(found[h][1], **labelled_meta(by_hash[h], found[h][0]), month=tx_month(found[h][1]))
            for h in by_hash if h in found]
    append_jsonl_gz(tmp, recs)
    tmp.replace(out)
    still = [h for h in by_hash if h not in found]
    log(f"labelled: wrote {len(recs)} to {out}; missing {len(still)} {still[:10]}; http={fn.stats}")


def build_windows(fn: FastNear, n_probes: int, log) -> list[dict]:
    first = fn.account_page(INTENTS, desc=False, limit=1)["account_txs"][0]
    last = fn.account_page(INTENTS, desc=True, limit=1)["account_txs"][0]
    lo, hi = first["tx_block_height"], last["tx_block_height"]
    probes = [(lo, int(first["tx_block_timestamp"])), (hi, int(last["tx_block_timestamp"]))]
    for i in range(1, n_probes):
        h = lo + (hi - lo) * i // n_probes
        rows = fn.account_page(INTENTS, desc=False, limit=1, from_tx_block_height=h)["account_txs"]
        if rows:
            probes.append((rows[0]["tx_block_height"], int(rows[0]["tx_block_timestamp"])))
    ws = month_windows(probes, lo, hi)
    for w in ws:
        w["txs_count"] = fn.account_page(INTENTS, desc=False, limit=1, from_tx_block_height=w["from_height"],
                                         to_tx_block_height=w["to_height"]).get("txs_count")
        log(f"window {w}")
    return ws


def cmd_normals(a) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    log = Logger(DATA / "collect.log")
    out = DATA / "normals.jsonl.gz"
    rng = random.Random(a.seed)
    stop = {"flag": False}

    def on_signal(signum, _frame):
        stop["flag"] = True
        log(f"signal {signum}: stopping after the current page")

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    rows = load_labels(a.labels)
    labelled = {r["tx_hash"] for r in rows}
    signers = labelled_signers(rows)
    attackers = attacker_ids(json.loads(a.attackers.read_text()))
    log(f"normals: excluding {len(labelled)} labelled hashes, {len(attackers)} attacker ids and "
        f"{len(signers)} labelled signers")

    size = repair_jsonl_gz(out)
    known: set[str] = set(labelled)
    counts: collections.Counter = collections.Counter()
    n_existing = 0
    for r in iter_jsonl_gz(out):
        known.add(tx_hash(r))
        counts[r["_meta"]["window"]] += 1
        n_existing += 1
    log(f"normals: resume with {n_existing} records ({size} bytes)")

    if n_existing == 0:
        excluded = collections.Counter()
        batch = []
        for d, t in seed_txs(a.scout, skip_dirs=("exploit_23",)):
            h = tx_hash(t)
            if h in known:
                excluded["dup_or_labelled"] += 1
                continue
            known.add(h)
            reason = exclusion_reason(t, attackers, signers)
            if reason:
                excluded[reason] += 1
                continue
            m = tx_month(t)
            batch.append(attach_meta(t, source=f"fastnear-seed:{d}", label=0, month=m, window=m, page_from=None))
            counts[m] += 1
        append_jsonl_gz(out, batch)
        n_existing = len(batch)
        log(f"normals: seeded {len(batch)} from scouting; excluded {dict(excluded)}")

    fn = FastNear(log=log)
    wpath = DATA / "windows.json"
    try:
        if wpath.exists():
            windows = json.loads(wpath.read_text())
        else:
            windows = build_windows(fn, a.probes, log)
            wpath.write_text(json.dumps(windows, indent=1))
    except Refused as e:
        log(f"normals: FastNEAR refused while building windows: {e}")
        return

    t0 = time.monotonic()
    deadline = t0 + a.max_minutes * 60
    total = sum(counts.values())
    pulled = 0
    excluded = collections.Counter()
    cursors: dict[str, str | None] = {}
    exhausted: set[str] = set()
    rounds = 0
    try:
        while total < a.target and time.monotonic() < deadline and not stop["flag"]:
            active = [w for w in windows if w["window"] not in exhausted]
            if not active:
                log("normals: every window exhausted")
                break
            rounds += 1
            for w in sorted(active, key=lambda w: counts[w["window"]]):
                if total >= a.target or time.monotonic() >= deadline or stop["flag"]:
                    break
                name = w["window"]
                small = (w.get("txs_count") or 0) <= a.small_window
                q = {"desc": False, "to_tx_block_height": w["to_height"]}
                if small:
                    q["from_tx_block_height"] = w["from_height"]
                    if cursors.get(name):
                        q["resume_token"] = cursors[name]
                    start = w["from_height"]
                else:
                    start = rng.randint(w["from_height"], w["to_height"])
                    q["from_tx_block_height"] = start
                page = fn.account_page(INTENTS, **q)
                rows = page.get("account_txs") or []
                if small:
                    cursors[name] = page.get("resume_token")
                    if not cursors[name] or not rows:
                        exhausted.add(name)
                hs = page_hashes(rows, known, a.per_page if not small else len(rows), rng)
                txs = dedupe_txs(fn.transactions(hs), known)
                keep = []
                for t in txs:
                    reason = exclusion_reason(t, attackers, signers)
                    if reason:
                        excluded[reason] += 1
                        continue
                    keep.append(attach_meta(t, source="fastnear", label=0, month=tx_month(t), window=name,
                                            page_from=start))
                append_jsonl_gz(out, keep)
                counts[name] += len(keep)
                total += len(keep)
                pulled += len(keep)
                if w.get("txs_count") and counts[name] >= 0.98 * w["txs_count"]:
                    exhausted.add(name)
            mins = (time.monotonic() - t0) / 60
            log(f"round {rounds}: total={total} pulled={pulled} in {mins:.1f} min "
                f"({pulled / max(mins, 1e-9):.0f} tx/min) excluded={dict(excluded)} "
                f"min/max per window={min(counts[w['window']] for w in windows)}/"
                f"{max(counts[w['window']] for w in windows)} exhausted={sorted(exhausted)} http={fn.stats}")
    except Refused as e:
        log(f"normals: FastNEAR refused, stopping: {e}")
    mins = (time.monotonic() - t0) / 60
    log(f"normals: done total={total} pulled={pulled} in {mins:.1f} min excluded={dict(excluded)} "
        f"per_window={dict(sorted(counts.items()))} http={fn.stats}")


def summarize(records: Iterable[dict]) -> dict:
    s = {"total": 0, "by_month": collections.Counter(), "by_flow": collections.Counter(),
         "by_status": collections.Counter(), "by_label": collections.Counter(), "by_role": collections.Counter(),
         "by_month_flow": collections.Counter(), "by_flow_status": collections.Counter()}
    for r in records:
        m = r.get("_meta") or {}
        month, flow = tx_month(r), flow_type(r)
        status = "failure" if any_receipt_failed(r) else "success"
        s["total"] += 1
        s["by_month"][month] += 1
        s["by_flow"][flow] += 1
        s["by_status"][status] += 1
        s["by_label"][str(m.get("label"))] += 1
        s["by_role"][str(m.get("role"))] += 1
        s["by_month_flow"][f"{month} {flow}"] += 1
        s["by_flow_status"][f"{flow} {status}"] += 1
    return {k: (dict(sorted(v.items())) if isinstance(v, collections.Counter) else v) for k, v in s.items()}


def cmd_stats(a) -> None:
    out = {}
    for name in ("labelled", "normals"):
        p = DATA / f"{name}.jsonl.gz"
        out[name] = summarize(iter_jsonl_gz(p))
        out[name]["file_bytes"] = p.stat().st_size if p.exists() else 0
    (DATA / "stats.json").write_text(json.dumps(out, indent=1))
    for name, s in out.items():
        print(f"== {name}: {s['total']} txs, {s['file_bytes'] / 1e6:.1f} MB")
        for k in ("by_label", "by_role", "by_flow", "by_status", "by_flow_status", "by_month"):
            print(f"  {k}: {json.dumps(s[k])}")


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="near.intents.collect")
    ap.add_argument("--scout", type=Path, help="scouting directory with bulk-access seeds (optional)")
    ap.add_argument("--labels", type=Path, default=LABELS, help="labelled txs JSONL (default: %(default)s)")
    ap.add_argument("--attackers", type=Path, default=ATTACKERS, help="attacker_accounts.json (default: %(default)s)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("labelled")
    n = sub.add_parser("normals")
    n.add_argument("--target", type=int, default=100_000)
    n.add_argument("--max-minutes", type=float, default=120)
    n.add_argument("--per-page", type=int, default=100, help="hashes kept per random-start index page of 200")
    n.add_argument("--small-window", type=int, default=2000, help="windows this small are read sequentially")
    n.add_argument("--probes", type=int, default=80)
    n.add_argument("--seed", type=int, default=20261114)
    sub.add_parser("stats")
    return ap


def main(argv=None) -> None:
    a = parser().parse_args(argv)
    {"labelled": cmd_labelled, "normals": cmd_normals, "stats": cmd_stats}[a.cmd](a)


if __name__ == "__main__":
    main(sys.argv[1:])
