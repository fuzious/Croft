"""Offline protocol investigation using recorded FastNEAR responses and the real frozen scorer.

Run from the repository root: uv run python -m near.demo.replay
Requires the frozen Intents artifacts from archives/near_intents.zip. No network,
wallet or keys are used. This is historical replay, not transaction simulation.
"""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from near.service import intents

RECORDING = Path(__file__).resolve().parents[1] / "service/fixtures/fastnear_recorded.json.gz"
EXPLOIT = "3k91uDpUiezxUe7hBgAR7kc3TBkToMZKGAiv6GqbtKiC"
NORMAL = "8tTzvGLMV7x1swmF2A5m3zDugCimdwmDrTXDTvKsJvj"
EXPLOITER = "20e6bfe4685d99004fc2095d3a0fc6158cd810ce8f801196141e183ed6e19d65"


def main() -> None:
    with gzip.open(RECORDING, "rt") as f:
        recording = json.load(f)
    answers = {(r["path"], json.dumps(r["body"], sort_keys=True)): r for r in recording["requests"]}

    def replay(path, body):
        key = (path, json.dumps(body, sort_keys=True))
        if key not in answers:
            raise RuntimeError(f"Request is not in the recording: {path}; no live fallback")
        r = answers[key]
        return r["status"], {}, r["text"].encode()

    intents.clear_cache()
    print("Historical FastNEAR replay recorded 2026-11-14; no live requests or payments.")
    print(json.dumps({"recording_sha256": hashlib.sha256(RECORDING.read_bytes()).hexdigest(),
                      "model": intents.model_info()}))
    for name, tx_hash, expected in (("exploit", EXPLOIT, "high"), ("normal", NORMAL, "low")):
        result = intents.score_hash(tx_hash, transport=replay)
        if result["label"] != expected:
            raise RuntimeError(f"{name}: expected {expected}, got {result['label']}")
        print(json.dumps({"case": name, "tx_hash": tx_hash, "label": result["label"],
                          "assessment": result["assessment"], "assessment_reason": result["assessment_reason"],
                          "evidence_coverage": result["evidence_coverage"],
                          "rules": [h["rule"] for h in result["rule_hits"]]}))

    value = intents.recent_activity(EXPLOITER, transport=replay)
    high = sum(t["label"] == "high" for t in value["txs"])
    if (high, value["n_scored"]) != (10, 20):
        raise RuntimeError(f"Expected 10 high / 20 scored; got {high} / {value['n_scored']}")
    print(json.dumps({"case": "account_activity", "account_id": EXPLOITER,
                      "high": high, "scored": value["n_scored"],
                      "assessments": {a: sum(t["assessment"] == a for t in value["txs"])
                                      for a in sorted({t["assessment"] for t in value["txs"]})}}))
    print("PASS: exploit high; normal low; account history 10/20 high.")
    print("Findings support protocol investigation. Low is not proof of safety; no chain state is changed.")


if __name__ == "__main__":
    try:
        main()
    except intents.ModelUnavailable as e:
        raise SystemExit(f"{e}\nUnpack archives/near_intents.zip from the repository root first.") from None
