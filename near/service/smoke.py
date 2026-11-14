"""Live smoke run of the oracle on real mainnet accounts, in-process (FastAPI TestClient), printing each response.
Not a unit test: it needs network and the free NearBlocks tier (about 6 requests a minute without
NEARBLOCKS_API_KEY), so it pauses between checks. `uv run python -m near.service.smoke [--pause 20]`."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time

KEYS = ("exists", "is_contract", "age_days", "tx_count", "code_changed_days", "prior_interactions",
        "onchain_blocked", "local_blocklist", "source", "code_risk")


def fresh_account(cfg) -> str | None:
    """An implicit account that just signed `near.create_account`: usually created minutes or days ago."""
    from .signals import SignalError, nearblocks
    try:
        txs = nearblocks(cfg, "/v3/accounts/near/txns", {"limit": 25}).get("data") or []
    except SignalError:
        return None
    return next((t["signer_account_id"] for t in txs if re.fullmatch(r"[0-9a-f]{64}", t["signer_account_id"])), None)


def show(title: str, body: dict) -> None:
    sig = body.get("signals", {})
    brief = {}
    for k in KEYS:
        s = sig.get(k)
        if s is not None:
            brief[k] = s["value"] if s["available"] else f"UNAVAILABLE ({s['error']})"
    print(f"\n=== {title}")
    print(json.dumps({"verdict": body.get("verdict"), "score": body.get("score"), "reasons": body.get("reasons"),
                      "model": body.get("model"), "signals": brief}, indent=1, default=str))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pause", type=float, default=20.0, help="seconds between checks (NearBlocks rate limit)")
    a = ap.parse_args()
    sys.stdout.reconfigure(line_buffering=True)
    tmp = tempfile.mkdtemp(prefix="oracle_smoke_")
    os.environ["ORACLE_BLOCKLIST_PATH"] = os.path.join(tmp, "blocklist.json")
    os.environ["ORACLE_ADMIN_TOKEN"] = "smoke-operator-token"
    from fastapi.testclient import TestClient

    from .app import CFG, app
    c = TestClient(app)
    print("health:", json.dumps(c.get("/v1/health").json()))

    snippet = {"src/lib.rs": "#[near_bindgen]\nimpl C {\n    pub fn set_owner(&mut self, owner: AccountId) {\n"
                             "        self.owner = owner;\n    }\n}\n"}
    r = c.post("/v1/analyze", json={"source_files": snippet}).json()
    print("\n=== analyze snippet (privileged setter, no auth):",
          json.dumps({k: r[k] for k in ("risk", "label", "model")}),
          json.dumps([(f["fn"], f["risk"], [h["detector"] for h in f["detector_hits"]]) for f in r["functions"]]))

    bad = "smoke-drainer.near"
    rep = c.post("/v1/report", json={"account_id": bad, "evidence_url": "https://example.com/smoke-evidence",
                                     "confirm": True}, headers={"Authorization": "Bearer smoke-operator-token"})
    print("\nreport (confirmed by operator token):", rep.status_code, json.dumps(rep.json()))
    anon = c.post("/v1/report", json={"account_id": bad, "evidence_url": "https://e.com/x", "confirm": True})
    print("report confirm without token:", anon.status_code)

    fresh = fresh_account(CFG)
    cases = [
        ("wrap.near: old contract, no NEP-330 metadata", {"receiver_id": "wrap.near", "agent_id": "wx-cruce.near",
                                                         "deposit_yocto": str(10**24)}),
        ("lst.rhealab.near: contract with pinned NEP-330 source", {"receiver_id": "lst.rhealab.near"}),
        ("token.sweat: contract with pinned NEP-330 source", {"receiver_id": "token.sweat"}),
        ("root.near: old EOA, 1 NEAR", {"receiver_id": "root.near", "agent_id": "wx-cruce.near",
                                        "deposit_yocto": str(10**24)}),
        ("root.near: same EOA, 500 NEAR, no prior interaction", {"receiver_id": "root.near",
                                                                 "agent_id": "wx-cruce.near",
                                                                 "deposit_yocto": str(500 * 10**24)}),
        (f"fresh account {fresh}", {"receiver_id": fresh} if fresh else None),
        ("nonexistent account", {"receiver_id": "no-such-account-oracle-smoke.near"}),
        (f"{bad}: on the local blocklist", {"receiver_id": bad}),
    ]
    for i, (title, req) in enumerate(cases):
        if req is None:
            print(f"\n=== {title}: skipped (could not discover one)")
            continue
        if i:
            time.sleep(a.pause)
        t0 = time.time()
        r = c.post("/v1/check", json=req)
        show(f"{title}  [{time.time() - t0:.1f}s, HTTP {r.status_code}]", r.json())


if __name__ == "__main__":
    main()
