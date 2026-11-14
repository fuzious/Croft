"""Local blocklist: reports with evidence, kept in one JSON file (default near/data/service/blocklist.json, env
ORACLE_BLOCKLIST_PATH). A report is `pending` until an operator confirms it; only confirmed reports block, so an
anonymous report cannot block an account by itself. `python -m near.service.blocklist list|confirm ID|dismiss ID`."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parents[1] / "data" / "service" / "blocklist.json"
STATUSES = {"pending", "confirmed", "dismissed"}
_lock = threading.Lock()


def _path(path=None) -> Path:
    return Path(path or os.environ.get("ORACLE_BLOCKLIST_PATH") or DEFAULT_PATH)


def _load(p: Path) -> dict:
    return json.loads(p.read_text()) if p.exists() else {"reports": []}


def _save(p: Path, db: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, indent=1))
    os.replace(tmp, p)


def add_report(account_id: str, evidence_url: str, evidence_sha256: str | None = None, reporter: str | None = None,
               note: str | None = None, confirmed: bool = False, path=None) -> dict:
    p = _path(path)
    with _lock:
        db = _load(p)
        r = {"id": len(db["reports"]), "account_id": account_id, "evidence_url": evidence_url,
             "evidence_sha256": evidence_sha256, "reporter": reporter, "note": note,
             "status": "confirmed" if confirmed else "pending", "created_at": int(time.time())}
        db["reports"].append(r)
        _save(p, db)
    return r


def set_status(report_id: int, status: str, path=None) -> dict:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {sorted(STATUSES)}")
    p = _path(path)
    with _lock:
        db = _load(p)
        if not 0 <= report_id < len(db["reports"]):
            raise KeyError(report_id)
        db["reports"][report_id]["status"] = status
        _save(p, db)
    return db["reports"][report_id]


def lookup(account_id: str, path=None) -> dict:
    """{blocked, confirmed: [reports], pending: n} for one account."""
    rs = [r for r in _load(_path(path))["reports"] if r["account_id"] == account_id]
    confirmed = [r for r in rs if r["status"] == "confirmed"]
    return {"blocked": bool(confirmed), "confirmed": confirmed, "pending": sum(r["status"] == "pending" for r in rs)}


def main(argv: list[str]) -> int:
    if argv[:1] == ["list"]:
        for r in _load(_path())["reports"]:
            print(json.dumps(r))
        return 0
    if len(argv) == 2 and argv[0] in ("confirm", "dismiss"):
        print(json.dumps(set_status(int(argv[1]), argv[0] + "ed")))
        return 0
    print(__doc__.strip().splitlines()[-1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
