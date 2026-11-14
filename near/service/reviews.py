"""Local demo review queue. Decisions are annotations, never on-chain policy."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/v1/reviews", tags=["Croft human review (demo)"])


@contextmanager
def database():
    path = Path(os.environ.get("ORACLE_REVIEW_DB", "data/human_reviews.sqlite3"))
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("""CREATE TABLE IF NOT EXISTS reviews (
            id TEXT PRIMARY KEY, evidence TEXT NOT NULL, account_id TEXT,
            created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            note TEXT NOT NULL DEFAULT '', reviewed_at TEXT, demo INTEGER NOT NULL DEFAULT 0
        )""")
        with db:
            yield db
    finally:
        db.close()


def enqueue(evidence: dict, account_id: str | None = None, *, demo: bool = False):
    if evidence.get("assessment") not in ("suspicious", "malicious_pattern"):
        return
    # Keep the original review evidence and decision stable across repeated scans.
    key = ("demo:" if demo else "") + evidence["tx_hash"]
    with database() as db:
        db.execute("""INSERT OR IGNORE INTO reviews
            (id, evidence, account_id, created_at, demo) VALUES (?, ?, ?, ?, ?)""",
            (key, json.dumps(evidence), account_id or evidence.get("signer_id"),
             datetime.now(timezone.utc).isoformat(), int(demo)))


def serialize(row):
    return {**dict(row), "evidence": json.loads(row["evidence"]), "demo": bool(row["demo"])}


@router.get("")
def list_reviews():
    with database() as db:
        return {"items": [serialize(row) for row in db.execute(
            "SELECT * FROM reviews ORDER BY created_at DESC")]}


class Decision(BaseModel):
    status: Literal["confirmed", "dismissed", "pending"]
    note: str = Field(min_length=1, max_length=2000)


@router.patch("/{review_id}")
def decide(review_id: str, decision: Decision):
    if not decision.note.strip():
        raise HTTPException(422, "Add a review note before saving a decision.")
    with database() as db:
        result = db.execute("UPDATE reviews SET status = ?, note = ?, reviewed_at = ? WHERE id = ?",
                            (decision.status, decision.note.strip(),
                             datetime.now(timezone.utc).isoformat(), review_id))
        if not result.rowcount:
            raise HTTPException(404, "Review not found")
        return serialize(db.execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone())


@router.post("/demo")
def load_demo():
    """Explicitly load labelled historical examples; never mix their IDs with live findings."""
    examples = Path(__file__).resolve().parents[1] / "human" / "examples.json"
    for evidence in json.loads(examples.read_text()):
        enqueue(evidence, demo=True)
    return list_reviews()
