import os
import threading
import time
import unittest
import unittest.mock

from fastapi.testclient import TestClient

from near.service import app as service
from near.service import intents, policy, signals

VULN = '''
#[near_bindgen]
impl Contract {
    pub fn on_withdraw(&mut self, account_id: AccountId, amount: U128) {
        self.balances.insert(&account_id, &amount.0);
    }
}
'''

SAFE = '''
#[near_bindgen]
impl Contract {
    pub fn get_total(&self) -> U128 {
        U128(self.total)
    }
}
'''


class DetectorRiskTest(unittest.TestCase):
    def test_noisy_or_of_severity_weights(self):
        w = service.THRESHOLDS["detector_weight"]
        self.assertEqual(service.detector_risk([]), 0.0)
        self.assertAlmostEqual(service.detector_risk([{"severity": "high"}]), w["high"])
        two = service.detector_risk([{"severity": "high"}, {"severity": "medium"}])
        self.assertAlmostEqual(two, 1 - (1 - w["high"]) * (1 - w["medium"]))

    def test_safe_source_scores_low(self):
        out = service.code_risk({"src/lib.rs": SAFE})
        self.assertEqual((out["risk"], out["label"]), (0.0, "low"))
        self.assertEqual(out["n_functions"], 1)

    def test_detectors_only_never_labels_high(self):
        hits = [{"severity": "high"}] * 5
        self.assertGreater(service.detector_risk(hits), service.THRESHOLDS["risk_high"])
        self.assertEqual(service.detectors_only_label(service.detector_risk(hits)), "medium")


class CheckSignalTest(unittest.TestCase):
    def test_brief_keeps_what_the_policy_needs(self):
        src = "#[near_bindgen]\nimpl Contract {\n    pub fn set_owner(&mut self, owner: AccountId) {\n        self.owner = owner;\n    }\n}\n"
        brief = service._brief(service.code_risk({"src/lib.rs": src}))
        sig = {"is_contract": {"value": True, "available": True}, "code_risk": {"value": brief, "available": True}}
        reasons = policy.decide(sig, network="sandbox")["reasons"]
        self.assertTrue(any("set_owner" in r for r in reasons), reasons)


class EndpointValidationTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(service.app)

    def test_analyze_returns_per_function_rows(self):
        r = self.client.post("/v1/analyze", json={"source_files": {"src/lib.rs": VULN + SAFE}})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual({f["fn"] for f in body["functions"]}, {"on_withdraw", "get_total"})
        self.assertIn("version", body["model"])

    def test_check_rejects_invalid_account_id(self):
        self.assertEqual(self.client.post("/v1/check", json={"receiver_id": "Bad Account!"}).status_code, 422)

    def test_report_rejects_non_http_evidence(self):
        r = self.client.post("/v1/report", json={"account_id": "x.near", "evidence_url": "file:///etc/passwd"})
        self.assertEqual(r.status_code, 422)

    def test_confirm_with_non_ascii_authorization_is_refused_not_500(self):
        with unittest.mock.patch.dict(os.environ, {"ORACLE_ADMIN_TOKEN": "t0ken"}):
            r = self.client.post("/v1/report", headers={"Authorization": "Bearer \u00e9".encode("utf8")},
                                 json={"account_id": "x.near", "evidence_url": "https://e/x", "confirm": True})
        self.assertEqual(r.status_code, 403)

    def test_health_shows_rpc_hosts_not_urls(self):
        body = self.client.get("/v1/health").json()
        self.assertNotIn("rpc_urls", body)
        self.assertTrue(all("/" not in h for h in body["rpc_hosts"]))

    def test_oversized_source_file_is_refused(self):
        big = "fn a() {}\n" * (service.MAX_FILE_BYTES // 10 + 1)
        self.assertEqual(self.client.post("/v1/analyze", json={"source_files": {"a.rs": big}}).status_code, 413)

    def test_source_caps_count_utf8_bytes_before_checking_live_signals(self):
        big = "\u00e9" * (service.MAX_FILE_BYTES // 2 + 1)
        with unittest.mock.patch.object(signals, "account_signals") as fetch:
            r = self.client.post("/v1/check", json={"receiver_id": "x.near", "source_files": {"a.rs": big}})
        self.assertEqual(r.status_code, 413)
        fetch.assert_not_called()

    def test_oversized_body_is_refused_before_parsing(self):
        r = self.client.post("/v1/analyze", content=b"x" * (service.MAX_BODY_BYTES + 1),
                             headers={"content-type": "application/json"})
        self.assertEqual(r.status_code, 413)

    def test_demo_page_is_served(self):
        r = self.client.get("/", follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn("Croft", r.text)


CLOSED_PORT = "http://127.0.0.1:9"   # nothing listens on the discard port: RPC and NearBlocks fail at once


class CheckIntentsTest(unittest.TestCase):
    """/v1/check on mainnet with RPC and NearBlocks unreachable and FastNEAR answered by a fake transport."""

    def setUp(self):
        self.client = TestClient(service.app)
        self.saved = (service.CFG, service.INTENTS_DEADLINE_S, intents.TRANSPORT)
        service.CFG = signals.load_config({"NEAR_NETWORK": "mainnet", "NEAR_RPC_URL": CLOSED_PORT,
                                           "NEARBLOCKS_API": CLOSED_PORT})
        intents.clear_cache()

    def tearDown(self):
        service.CFG, service.INTENTS_DEADLINE_S, intents.TRANSPORT = self.saved
        intents.clear_cache()

    def intents_reason(self, body) -> str:
        return next((r for r in body["reasons"] if "NEAR Intents" in r), "")

    def test_fastnear_body_of_the_wrong_shape_is_a_warn_not_a_500(self):
        for raw in (b"[]", b'"x"', b'{"account_txs":[{"nohash":1}]}', b'{"account_txs":"abc"}'):
            with self.subTest(raw):
                intents.TRANSPORT = lambda path, body, raw=raw: (200, {}, raw)
                r = self.client.post("/v1/check", json={"receiver_id": "someone.near"})
                self.assertEqual(r.status_code, 200, r.text)
                b = r.json()
                self.assertFalse(b["signals"]["intents_activity"]["available"])
                self.assertEqual(b["verdict"], "warn")
                self.assertIn("could not be read", self.intents_reason(b))

    def test_slow_fastnear_times_out_into_a_warn(self):
        release = threading.Event()

        def stalled(path, body):
            release.wait(10)
            raise OSError("test finished")

        intents.TRANSPORT = stalled
        service.INTENTS_DEADLINE_S = 0.3
        t0 = time.monotonic()
        try:
            r = self.client.post("/v1/check", json={"receiver_id": "someone.near"})
        finally:
            release.set()
        self.assertLess(time.monotonic() - t0, 5.0)
        self.assertEqual(r.status_code, 200, r.text)
        ia = r.json()["signals"]["intents_activity"]
        self.assertFalse(ia["available"])
        self.assertIn("FastNEAR timed out", ia["error"])
        self.assertIn("FastNEAR timed out", self.intents_reason(r.json()))


if __name__ == "__main__":
    unittest.main()
