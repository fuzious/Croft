"""NEAR Intents scoring in the oracle. fixtures/fastnear_recorded.json.gz holds real FastNEAR responses recorded on
2026-11-14: the 2026-10-01 exploit tx 3k91uD..., a normal PoA deposit 8tTzvG..., a well-formed hash FastNEAR does not
know, and the exploiter account's 40 most recent index rows with their full transactions (two batches of 20). The
replay transport answers only those exact requests; nothing in near.service is mocked."""
import gzip
import json
import socket
import threading
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from fastapi.testclient import TestClient

from near.service import app as service
from near.service import intents
from near.service.policy import THRESHOLDS, decide
from near.service.test_policy import eoa

FIX = Path(__file__).parent / "fixtures" / "fastnear_recorded.json.gz"
MODEL = Path(__file__).resolve().parents[1] / "models" / "intents_v1.pkl"
EXPLOIT = "3k91uDpUiezxUe7hBgAR7kc3TBkToMZKGAiv6GqbtKiC"
NORMAL = "8tTzvGLMV7x1swmF2A5m3zDugCimdwmDrTXDTvKsJvj"
UNKNOWN = "11111111111111111111111111111112"
EXPLOITER = "20e6bfe4685d99004fc2095d3a0fc6158cd810ce8f801196141e183ed6e19d65"
CLOSED_PORT = "http://127.0.0.1:9"   # nothing listens on the discard port: a real connection error


class Replay:
    """Transport (path, body) -> (status, headers, bytes) answering from the recorded FastNEAR responses."""

    def __init__(self, path=FIX):
        with gzip.open(path, "rt") as f:
            recs = json.load(f)["requests"]
        self.answers = {self.key(r["path"], r["body"]): (r["status"], {}, r["text"].encode()) for r in recs}
        self.calls: list[str] = []

    @staticmethod
    def key(path, body) -> str:
        return path + " " + json.dumps(body, sort_keys=True)

    def __call__(self, path, body):
        self.calls.append(path)
        k = self.key(path, body)
        if k not in self.answers:
            raise AssertionError(f"request was not recorded: {k[:160]}")
        return self.answers[k]


class Answer:
    """Transport answering HTTP 200 with a fixed body per path, as a FastNEAR that sends unexpected data would."""

    def __init__(self, bodies: dict[str, bytes]):
        self.bodies = bodies
        self.calls: list[str] = []

    def __call__(self, path, body):
        self.calls.append(path)
        return 200, {}, self.bodies[path]


class TrickleServer:
    """A real HTTP server on 127.0.0.1 that sends a 200 answer one byte every `gap` seconds: from the status line on
    (`trickle_head`) or from the body on (headers at once). With gap 0 it sends the whole answer at once. Each
    connection stays open until close(), so the client never sees the answer end early."""

    def __init__(self, gap: float = 0.25, trickle_head: bool = False, size: int = 20):
        self.gap, self.trickle_head, self.size = gap, trickle_head, size
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        self.stop = threading.Event()
        self.threads = [threading.Thread(target=self.serve)]
        self.threads[0].start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            t = threading.Thread(target=self.answer, args=(conn,))
            self.threads.append(t)
            t.start()

    def answer(self, conn):
        head = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: %d\r\n\r\n" % self.size
        body = b" " * self.size
        with conn:
            try:
                conn.recv(65536)
                if not self.gap:
                    conn.sendall(head + body)
                else:
                    if not self.trickle_head:
                        conn.sendall(head)
                    for b in (head + body if self.trickle_head else body):
                        if self.stop.wait(self.gap):
                            return
                        conn.sendall(bytes([b]))
                self.stop.wait(10)
            except OSError:
                pass

    def close(self):
        self.stop.set()
        self.threads[0].join()
        for t in self.threads[1:]:
            t.join()
        self.sock.close()


def recorded_tx(tx_hash: str) -> dict:
    status, _, raw = Replay().answers[Replay.key("/transactions", {"tx_hashes": [tx_hash]})]
    return json.loads(raw)["transactions"][0]


class TxHashTest(unittest.TestCase):
    def test_real_hashes_are_valid(self):
        for h in (EXPLOIT, NORMAL, UNKNOWN):
            self.assertTrue(intents.valid_tx_hash(h), h)

    def test_rejects_non_base58_and_wrong_length(self):
        for h in ("", "0" * 44, "O" * 44, "l" * 44, EXPLOIT[:-1] + "!", "1" * 31, "1" * 33, EXPLOIT + "1",
                  "z" * 44, 123, None):
            self.assertFalse(intents.valid_tx_hash(h), h)


class TouchesIntentsTest(unittest.TestCase):
    def test_exploit_and_normal_deposit_touch_intents(self):
        self.assertTrue(intents.touches_intents(recorded_tx(EXPLOIT)))
        self.assertTrue(intents.touches_intents(recorded_tx(NORMAL)))

    def test_plain_transfer_does_not(self):
        tx = {"transaction": {"signer_id": "a.near", "receiver_id": "b.near"},
              "receipts": [{"receipt": {"predecessor_id": "a.near", "receiver_id": "b.near"}}]}
        self.assertFalse(intents.touches_intents(tx))


class AssessmentTest(unittest.TestCase):
    def tx(self, supported=True, complete=True):
        return {"transaction": {"hash": NORMAL, "receiver_id": "intents.near" if supported else "other.near"},
                "receipts": [], "execution_outcome": {"outcome": {
                    "receipt_ids": [] if complete else ["missing"], "logs": [], "status": {"SuccessValue": ""}}}}

    def result(self, label="low", high_rule=False):
        return {"label": label, "rule_hits": [{"rule": "credit_kept", "severity": "high"}] if high_rule else []}

    def test_assessments_respect_protocol_and_receipt_coverage(self):
        cases = [
            (False, True, "high", True, "unsupported"),
            (True, True, "high", True, "malicious_pattern"),
            (True, False, "high", True, "malicious_pattern"),
            (True, True, "high", False, "suspicious"),
            (True, True, "medium", False, "suspicious"),
            (True, True, "low", False, "no_known_pattern"),
            (True, False, "low", False, "inconclusive"),
            (True, False, "medium", False, "inconclusive"),
        ]
        for supported, complete, label, high_rule, expected in cases:
            with self.subTest(expected=expected, complete=complete):
                out = intents.assessment(self.tx(supported, complete), self.result(label, high_rule))
                self.assertEqual(out["assessment"], expected)
                self.assertEqual(out["scope"]["protocol_supported"], supported)
                self.assertEqual(out["evidence_coverage"]["receipts_complete"], complete)
                if not complete:
                    self.assertEqual(out["confidence"]["level"], "limited")

    def test_pending_outcome_is_not_complete_evidence(self):
        tx = self.tx()
        tx["execution_outcome"]["outcome"]["status"] = {"Unknown": ""}
        out = intents.assessment(tx, self.result())
        self.assertEqual(out["assessment"], "inconclusive")
        self.assertEqual(out["evidence_coverage"]["pending_outcomes"], 1)

    def test_receipt_referenced_only_by_success_status_is_missing(self):
        tx = self.tx()
        tx["execution_outcome"]["outcome"]["status"] = {"SuccessReceiptId": "missing"}
        self.assertFalse(intents.receipts_complete(tx))

    def test_neutral_score_alias_preserves_assessment_for_unsupported_transaction(self):
        tx = self.tx(supported=False)
        result = self.result() | {"risk": 0.1, "flow": "other", "top_features": [],
                                  "anomaly_score": 0.1, "anomaly_percentile": 0.1}
        with patch.object(intents, "TRANSPORT", Answer({"/transactions": json.dumps({"transactions": [tx]}).encode()})), \
                patch.object(intents, "score", return_value=result), patch.object(intents, "model_info", return_value={}):
            client = TestClient(service.app)
            canonical = client.post("/v1/transactions/score", json={"tx_hash": NORMAL})
            legacy = client.post("/v1/intents/score", json={"tx_hash": NORMAL})
        self.assertEqual(canonical.status_code, 200, canonical.text)
        self.assertEqual(canonical.json(), legacy.json())
        self.assertEqual(canonical.json()["assessment"], "unsupported")


@unittest.skipUnless(MODEL.exists(), "frozen intents model not present (near/models/intents_v1.pkl)")
class ActivityTest(unittest.TestCase):
    def setUp(self):
        intents.clear_cache()

    def tearDown(self):
        intents.clear_cache()

    def test_exploiter_recent_intents_txs_include_high_exploit_txs(self):
        replay = Replay()
        s = intents.activity_signal(EXPLOITER, transport=replay)
        self.assertTrue(s["available"], s)
        v = s["value"]
        self.assertLessEqual(len(replay.calls), THRESHOLDS["intents_max_requests"])
        self.assertLessEqual(v["n_scored"], THRESHOLDS["intents_recent_txs"])
        self.assertGreater(v["n_scored"], 0)
        high = {t["tx_hash"] for t in v["txs"] if t["label"] == "high"}
        # the 40 latest index rows hold 10 labelled exploit txs (all high) and Intents withdrawals (low)
        exploit_txs = {"GAQKwHdTaLPyvvAMCGfmcyPcR8rptuXu1mCRwz7UCQEG", "CWhtCr8ziTJJ4qbXGtZ3bBwzWtVa6rRAp7Q8ARgAfoDg",
                       "bMdkzhZf7tQZbXNnXcAnuJaLyTxaCq8W9BnTh28EaDr"}
        self.assertTrue(exploit_txs <= high, v["txs"])
        self.assertEqual(len(high), 10)
        self.assertEqual(v["txs"][0]["tx_hash"], "5d1VV4tyFh3xWomy2tWJbG9qfLDaRdbksjedUZ3A3j3o")  # newest first

    def test_second_check_is_served_from_cache(self):
        intents.activity_signal(EXPLOITER, transport=Replay())
        replay = Replay()
        s = intents.activity_signal(EXPLOITER, transport=replay)
        self.assertTrue(s["available"])
        self.assertEqual(replay.calls, [])

    def test_unreachable_fastnear_is_unavailable_not_safe(self):
        s = intents.activity_signal("someone.near", transport=intents.transport(CLOSED_PORT, timeout=2.0))
        self.assertFalse(s["available"])
        self.assertIn("FastNEAR", s["error"])
        self.assertIsNone(s["value"])


ONE_ROW = json.dumps({"account_txs": [{"transaction_hash": NORMAL}]}).encode()


class DeadlineTest(unittest.TestCase):
    """Each FastNEAR request ends within its timeout of wall-clock time, however slowly the server answers."""

    def setUp(self):
        intents.clear_cache()

    def tearDown(self):
        intents.clear_cache()

    def serve(self, **kw) -> TrickleServer:
        server = TrickleServer(**kw)
        self.addCleanup(server.close)
        return server

    def assert_times_out_within(self, server, timeout=1.0):
        send = intents.transport(server.url, timeout=timeout)
        t0 = time.monotonic()
        with self.assertRaises(TimeoutError) as cm:
            send("/account", {"account_id": "someone.near"})
        self.assertLess(time.monotonic() - t0, timeout + 0.5)
        self.assertIn(f"did not answer within {timeout:g} s", str(cm.exception))

    def test_trickled_body_ends_within_the_timeout(self):
        self.assert_times_out_within(self.serve(gap=0.25))

    def test_trickled_status_line_and_headers_end_within_the_timeout(self):
        self.assert_times_out_within(self.serve(gap=0.25, trickle_head=True, size=0))

    def test_body_over_the_size_cap_is_refused(self):
        send = intents.transport(self.serve(gap=0, size=5000).url, timeout=2.0, max_bytes=1000)
        with self.assertRaises(ValueError) as cm:
            send("/account", {"account_id": "someone.near"})
        self.assertIn("larger than 1000 bytes", str(cm.exception))

    def test_trickling_fastnear_is_unavailable_within_the_timeout(self):
        t0 = time.monotonic()
        s = intents.activity_signal("someone.near",
                                    transport=intents.transport(self.serve(gap=0.25).url, timeout=1.0))
        self.assertLess(time.monotonic() - t0, 1.5)
        self.assertFalse(s["available"])
        self.assertIn("FastNEAR did not answer within 1 s", s["error"])


class PartialReadTest(unittest.TestCase):
    """A /transactions answer missing some of the requested hashes is unreadable and is not cached."""

    def setUp(self):
        intents.clear_cache()

    def tearDown(self):
        intents.clear_cache()

    def partial(self, keep: int):
        replay = Replay()

        def send(path, body):
            if path != "/transactions":
                return replay(path, body)
            status, headers, raw = replay(path, body)
            txs = json.loads(raw)["transactions"]
            return status, headers, json.dumps({"transactions": txs[:keep] + [None] * (len(txs) - keep)}).encode()

        return send

    def test_missing_transactions_make_the_signal_unavailable(self):
        for keep in (0, 19):
            with self.subTest(keep):
                intents.clear_cache()
                s = intents.activity_signal(EXPLOITER, transport=self.partial(keep), now=1000.0)
                self.assertFalse(s["available"], s)
                self.assertIn(f"FastNEAR returned {keep} of 20 transactions", s["error"])
                self.assertEqual(decide(eoa(intents_activity=s))["verdict"], "warn")

    def test_partial_read_is_not_cached(self):
        intents.activity_signal(EXPLOITER, transport=self.partial(0), now=1000.0)
        replay = Replay()
        intents.activity_signal(EXPLOITER, transport=replay, now=1000.0)
        self.assertTrue(replay.calls)


class UnexpectedBodyTest(unittest.TestCase):
    """An HTTP 200 from FastNEAR with a body of the wrong shape is an unreadable signal (which warns), not a crash."""

    def setUp(self):
        intents.clear_cache()

    def tearDown(self):
        intents.clear_cache()

    def assert_unreadable_and_warns(self, s):
        self.assertFalse(s["available"], s)
        self.assertIn("FastNEAR", s["error"])
        self.assertLessEqual(len(s["error"]), 300)
        d = decide(eoa(intents_activity=s))
        self.assertEqual(d["verdict"], "warn", d["reasons"])
        self.assertTrue(any("NEAR Intents" in r for r in d["reasons"]), d["reasons"])

    def test_account_index_of_the_wrong_shape(self):
        for body in (b"[]", b'"x"', b'{}', b'{"error":"unavailable"}', b'{"account_txs":null}',
                     b'{"account_txs":[{"nohash":1}]}', b'{"account_txs":"abc"}',
                     b'{"account_txs":[{"transaction_hash":{"a":1}}]}',
                     b'{"account_txs":[{"transaction_hash":"not-a-hash"}]}'):
            with self.subTest(body):
                self.assert_unreadable_and_warns(
                    intents.activity_signal("someone.near", transport=Answer({"/account": body})))

    def test_transactions_of_the_wrong_shape(self):
        for body in (b'"x"', b'{}', b'{"transactions":null}', b'{"transactions":"abc"}',
                     b'{"transactions":[{"transaction":[]}]}',
                     b'{"transactions":[{"transaction":{"hash":"H"},"receipts":"abc"}]}'):
            with self.subTest(body):
                answer = Answer({"/account": ONE_ROW, "/transactions": body})
                self.assert_unreadable_and_warns(intents.activity_signal("someone.near", transport=answer))

    def test_unrequested_transaction_cannot_contaminate_account_history(self):
        body = json.dumps({"transactions": [recorded_tx(NORMAL), recorded_tx(EXPLOIT)]}).encode()
        answer = Answer({"/account": ONE_ROW, "/transactions": body})
        s = intents.activity_signal("someone.near", transport=answer)
        self.assert_unreadable_and_warns(s)
        self.assertIn("not requested", s["error"])

    def test_duplicate_transaction_keeps_the_copy_with_most_receipts(self):
        # FastNEAR repeats an in-flight tx, each copy with the receipts it had seen so far.
        full = recorded_tx(EXPLOIT)
        partial = json.loads(json.dumps(full))
        partial["receipts"] = partial["receipts"][:1]
        body = json.dumps({"transactions": [partial, full, partial]}).encode()
        txs = intents._Client(Answer({"/transactions": body})).transactions([EXPLOIT])
        self.assertEqual(len(txs), 1)
        self.assertEqual(len(txs[0]["receipts"]), len(full["receipts"]))

    def test_malformed_transaction_response_is_502_not_not_found(self):
        saved = intents.TRANSPORT
        self.addCleanup(setattr, intents, "TRANSPORT", saved)
        for body in (b'{}', b'{"transactions":null}'):
            with self.subTest(body):
                intents.TRANSPORT = Answer({"/transactions": body})
                r = TestClient(service.app).post("/v1/intents/score", json={"tx_hash": NORMAL})
                self.assertEqual(r.status_code, 502, r.text)

    def test_missing_receipt_evidence_cannot_turn_an_exploit_into_low_risk(self):
        saved = intents.TRANSPORT
        self.addCleanup(setattr, intents, "TRANSPORT", saved)
        for mutation in ("missing_receipts", "missing_outcome", "missing_logs"):
            with self.subTest(mutation):
                tx = recorded_tx(EXPLOIT)
                if mutation == "missing_receipts":
                    tx.pop("receipts")
                elif mutation == "missing_outcome":
                    tx["receipts"][0].pop("execution_outcome")
                else:
                    tx["receipts"][0]["execution_outcome"]["outcome"].pop("logs")
                body = json.dumps({"transactions": [tx]}).encode()
                intents.TRANSPORT = Answer({"/transactions": body})
                r = TestClient(service.app).post("/v1/intents/score", json={"tx_hash": EXPLOIT})
                self.assertEqual(r.status_code, 502, r.text)
                self.assertIn("incomplete receipt graph", r.json()["detail"])


DANGLING = "J9RYnzQb4QBdz3MU8WwAXNydVJjtvyNn6QGcU1cNPDuY"
DANGLING_BODY = gzip.decompress((FIX.parent / "fastnear_dangling_receipt.json.gz").read_bytes())


@unittest.skipUnless(MODEL.exists(), "frozen intents model not present (near/models/intents_v1.pkl)")
class OmittedReceiptTest(unittest.TestCase):
    """FastNEAR leaves out some receipts that intents.near spawns (5 of the first 30,000 recorded normal txs, among
    them the real mainnet tx J9RYnz... in fixtures/fastnear_dangling_receipt.json.gz). Such a tx is still scored, and
    says so: a missing receipt can only hide evidence, so its label is a lower bound."""

    def setUp(self):
        intents.clear_cache()
        self.saved = intents.TRANSPORT
        self.addCleanup(setattr, intents, "TRANSPORT", self.saved)
        self.addCleanup(intents.clear_cache)
        self.client = TestClient(service.app)

    def test_real_tx_with_an_omitted_receipt_is_scored_and_marked(self):
        intents.TRANSPORT = Answer({"/transactions": DANGLING_BODY})
        r = self.client.post("/v1/intents/score", json={"tx_hash": DANGLING})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((r.json()["label"], r.json()["receipts_complete"]), ("low", False))
        self.assertEqual(r.json()["assessment"], "inconclusive")
        self.assertGreater(r.json()["evidence_coverage"]["missing_receipts"], 0)

    def test_receiver_history_with_an_omitted_receipt_stays_readable(self):
        index = json.dumps({"account_txs": [{"transaction_hash": DANGLING}]}).encode()
        s = intents.activity_signal("someone.near", transport=Answer({"/account": index, "/transactions": DANGLING_BODY}))
        self.assertTrue(s["available"], s)
        self.assertEqual([(t["tx_hash"], t["receipts_complete"]) for t in s["value"]["txs"]], [(DANGLING, False)])

    def test_exploit_with_an_omitted_receipt_still_scores_high(self):
        tx = recorded_tx(EXPLOIT)
        tx["receipts"].pop()
        intents.TRANSPORT = Answer({"/transactions": json.dumps({"transactions": [tx]}).encode()})
        r = self.client.post("/v1/intents/score", json={"tx_hash": EXPLOIT})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((r.json()["label"], r.json()["receipts_complete"]), ("high", False))
        self.assertEqual(r.json()["assessment"], "malicious_pattern")
        self.assertEqual(r.json()["confidence"]["level"], "limited")


EMPTY_INDEX = json.dumps({"account_txs": []}).encode()


class CacheTest(unittest.TestCase):
    def setUp(self):
        intents.clear_cache()
        self.saved = intents.CACHE_ENTRIES
        intents.CACHE_ENTRIES = 2

    def tearDown(self):
        intents.CACHE_ENTRIES = self.saved
        intents.clear_cache()

    def read(self, receiver_id) -> int:
        answer = Answer({"/account": EMPTY_INDEX})
        self.assertTrue(intents.activity_signal(receiver_id, transport=answer, now=1000.0)["available"])
        return len(answer.calls)

    def test_least_recently_read_receiver_is_evicted_first(self):
        self.assertEqual([self.read("a.near"), self.read("b.near")], [1, 1])
        self.assertEqual(self.read("a.near"), 0)    # cached; a is now the most recently read
        self.assertEqual(self.read("c.near"), 1)    # evicts b, the least recently read
        self.assertEqual(self.read("a.near"), 0)
        self.assertEqual(self.read("c.near"), 0)
        self.assertEqual(self.read("b.near"), 1)

    def test_unreadable_reads_are_not_cached(self):
        intents.activity_signal("a.near", transport=Answer({"/account": b"[]"}), now=1000.0)
        self.assertEqual(self.read("a.near"), 1)


@unittest.skipUnless(MODEL.exists(), "frozen intents model not present (near/models/intents_v1.pkl)")
class ScoreEndpointTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(service.app)
        self.saved = intents.TRANSPORT
        intents.TRANSPORT = Replay()

    def tearDown(self):
        intents.TRANSPORT = self.saved

    def test_exploit_tx_scores_high_with_its_rules(self):
        r = self.client.post("/v1/intents/score", json={"tx_hash": EXPLOIT})
        self.assertEqual(r.status_code, 200, r.text)
        b = r.json()
        self.assertEqual((b["label"], b["flow_type"]), ("high", "deposit"))
        self.assertEqual(b["risk"], 1.0)
        rules = {h["rule"] for h in b["rule_hits"]}
        self.assertTrue({"failed_resolve_callback", "credit_kept", "log_limit"} <= rules, rules)
        man = json.loads(MODEL.with_suffix(".json").read_text())
        self.assertEqual(b["model"], {"version": "intents_v1", "sha256": man["pkl_sha256"]})
        self.assertTrue(b["touches_intents"])
        self.assertEqual(b["assessment"], "malicious_pattern")
        self.assertTrue(b["top_features"])

    def test_normal_deposit_scores_low(self):
        r = self.client.post("/v1/intents/score", json={"tx_hash": NORMAL, "sender_id": "bridge-mng.near"})
        self.assertEqual(r.status_code, 200, r.text)
        b = r.json()
        self.assertEqual((b["label"], b["flow_type"], b["rule_hits"]), ("low", "deposit", []))
        self.assertIs(b["sender_matches"], True)
        self.assertIs(b["receipts_complete"], True)
        self.assertEqual(b["assessment"], "no_known_pattern")

    def test_sender_mismatch_is_reported(self):
        b = self.client.post("/v1/intents/score", json={"tx_hash": NORMAL, "sender_id": "other.near"}).json()
        self.assertIs(b["sender_matches"], False)

    def test_unknown_hash_is_404(self):
        r = self.client.post("/v1/intents/score", json={"tx_hash": UNKNOWN})
        self.assertEqual(r.status_code, 404)
        self.assertIn("not found", r.json()["detail"])

    def test_fastnear_down_is_502_with_reason(self):
        intents.TRANSPORT = intents.transport(CLOSED_PORT, timeout=2.0)
        r = self.client.post("/v1/intents/score", json={"tx_hash": EXPLOIT})
        self.assertEqual(r.status_code, 502)
        self.assertIn("FastNEAR", r.json()["detail"])

    def test_fastnear_timeout_is_504_within_the_timeout(self):
        server = TrickleServer(gap=0.25)
        self.addCleanup(server.close)
        intents.TRANSPORT = intents.transport(server.url, timeout=1.0)
        t0 = time.monotonic()
        r = self.client.post("/v1/intents/score", json={"tx_hash": EXPLOIT})
        self.assertLess(time.monotonic() - t0, 1.5)
        self.assertEqual(r.status_code, 504, r.text)
        self.assertIn("FastNEAR did not answer within 1 s", r.json()["detail"])

    def test_tx_of_a_shape_the_model_cannot_score_is_502_with_a_short_reason(self):
        junk = "JUNK" * 500
        for i, tx in enumerate((
                {"transaction": {"hash": EXPLOIT, "receiver_id": "intents.near", "actions": junk}, "receipts": junk},
                {"transaction": {"hash": EXPLOIT, "receiver_id": "intents.near"}, "receipts": [{"receipt": junk}]})):
            with self.subTest(i):
                intents.TRANSPORT = Answer({"/transactions": json.dumps({"transactions": [tx]}).encode()})
                r = self.client.post("/v1/intents/score", json={"tx_hash": EXPLOIT})
                self.assertEqual(r.status_code, 502, r.text)
                detail = r.json()["detail"]
                self.assertIn("could not be scored", detail)
                self.assertNotIn("JUNK", detail)
                self.assertLessEqual(len(detail), 200)

    def test_missing_model_manifest_is_503(self):
        saved = intents.MODEL_JSON
        intents.MODEL_JSON = MODEL.with_name("missing_intents_model.json")
        try:
            r = self.client.post("/v1/intents/score", json={"tx_hash": EXPLOIT})
        finally:
            intents.MODEL_JSON = saved
        self.assertEqual(r.status_code, 503, r.text)
        self.assertIn("intents model unavailable", r.json()["detail"])


class ScoreValidationTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(service.app)

    def test_rejects_malformed_hash(self):
        for h in ("not a hash", "0" * 44, EXPLOIT[:-2], "1" * 33):
            with self.subTest(h):
                self.assertEqual(self.client.post("/v1/intents/score", json={"tx_hash": h}).status_code, 422)

    def test_rejects_invalid_sender(self):
        r = self.client.post("/v1/intents/score", json={"tx_hash": EXPLOIT, "sender_id": "Bad Sender!"})
        self.assertEqual(r.status_code, 422)

    def test_requires_tx_hash(self):
        self.assertEqual(self.client.post("/v1/intents/score", json={}).status_code, 422)


SCAN_KEYS = {"account_id", "n_scored", "n_index_rows", "counts", "txs", "model", "assessment_counts", "n_incomplete", "scope", "detector"}
SCAN_TX_KEYS = {"tx_hash", "label", "risk", "flow", "rules", "receipts_complete", "assessment", "assessment_reason",
                "evidence_coverage", "scope", "confidence", "baseline", "accounting", "history", "attack_categories"}


class ScanEndpointTest(unittest.TestCase):
    """POST /v1/intents/scan: an account's latest transactions that touch NEAR Intents, scored, with FastNEAR answered
    by the recorded responses or by a failing transport."""

    def setUp(self):
        self.client = TestClient(service.app)
        self.saved = intents.TRANSPORT
        self.addCleanup(setattr, intents, "TRANSPORT", self.saved)
        self.addCleanup(intents.clear_cache)
        intents.clear_cache()

    def scan(self, account_id):
        return self.client.post("/v1/intents/scan", json={"account_id": account_id})

    @unittest.skipUnless(MODEL.exists(), "frozen intents model not present (near/models/intents_v1.pkl)")
    def test_exploiter_scan_counts_the_high_exploit_txs(self):
        intents.TRANSPORT = Replay()
        r = self.scan(EXPLOITER)
        self.assertEqual(r.status_code, 200, r.text)
        b = r.json()
        self.assertEqual(set(b), SCAN_KEYS)
        self.assertEqual(b["account_id"], EXPLOITER)
        self.assertEqual(b["n_index_rows"], THRESHOLDS["intents_index_rows"])
        self.assertEqual(b["n_scored"], len(b["txs"]))
        self.assertLessEqual(b["n_scored"], THRESHOLDS["intents_recent_txs"])
        self.assertEqual(b["counts"]["high"], 10)
        self.assertEqual(set(b["counts"]), {"high", "medium", "low"})
        self.assertEqual(sum(b["counts"].values()), b["n_scored"])
        self.assertEqual(sum(b["assessment_counts"].values()), b["n_scored"])
        self.assertEqual(b["assessment_counts"]["malicious_pattern"], 10)
        for label in ("high", "medium", "low"):
            self.assertEqual(b["counts"][label], sum(t["label"] == label for t in b["txs"]), label)
        self.assertTrue(all(set(t) == SCAN_TX_KEYS for t in b["txs"]), b["txs"][0])
        self.assertEqual(b["txs"][0]["tx_hash"], "5d1VV4tyFh3xWomy2tWJbG9qfLDaRdbksjedUZ3A3j3o")  # newest first
        man = json.loads(MODEL.with_suffix(".json").read_text())
        self.assertEqual(b["model"], {"version": "intents_v1", "sha256": man["pkl_sha256"]})

    @unittest.skipUnless(MODEL.exists(), "frozen intents model not present (near/models/intents_v1.pkl)")
    def test_second_scan_is_served_from_the_activity_cache(self):
        intents.TRANSPORT = Replay()
        first = self.scan(EXPLOITER).json()
        intents.TRANSPORT = replay = Replay()
        r = self.scan(EXPLOITER)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(replay.calls, [])
        self.assertEqual(r.json(), first)

    def test_account_with_no_intents_txs_scans_empty(self):
        intents.TRANSPORT = Answer({"/account": EMPTY_INDEX})
        r = self.scan("someone.near")
        self.assertEqual(r.status_code, 200, r.text)
        b = r.json()
        self.assertEqual((b["n_scored"], b["n_index_rows"], b["txs"]), (0, 0, []))
        self.assertEqual(b["counts"], {"high": 0, "medium": 0, "low": 0})
        self.assertEqual(sum(b["assessment_counts"].values()), 0)
        alias = self.client.post("/v1/protocols/scan", json={"account_id": "someone.near"})
        self.assertEqual(alias.json(), b)

    @unittest.skipUnless(MODEL.exists(), "frozen intents model not present")
    def test_incomplete_low_is_counted_as_inconclusive_not_no_known_pattern(self):
        index = json.dumps({"account_txs": [{"transaction_hash": DANGLING}]}).encode()
        intents.TRANSPORT = Answer({"/account": index, "/transactions": DANGLING_BODY})
        r = self.scan("someone.near")
        self.assertEqual(r.status_code, 200, r.text)
        b = r.json()
        self.assertEqual(b["n_incomplete"], 1)
        self.assertEqual(b["assessment_counts"]["inconclusive"], 1)
        self.assertEqual(b["assessment_counts"]["no_known_pattern"], 0)

    def test_rejects_invalid_account_id(self):
        for account_id in ("Bad Account!", "a", "x" * 65, "UPPER.near", "a..near", ""):
            with self.subTest(account_id):
                self.assertEqual(self.scan(account_id).status_code, 422)
        self.assertEqual(self.client.post("/v1/intents/scan", json={}).status_code, 422)

    def test_fastnear_down_is_502_with_reason(self):
        intents.TRANSPORT = intents.transport(CLOSED_PORT, timeout=2.0)
        r = self.scan("someone.near")
        self.assertEqual(r.status_code, 502, r.text)
        self.assertIn("FastNEAR", r.json()["detail"])

    def test_fastnear_timeout_is_504_within_the_timeout(self):
        server = TrickleServer(gap=0.25)
        self.addCleanup(server.close)
        intents.TRANSPORT = intents.transport(server.url, timeout=1.0)
        t0 = time.monotonic()
        r = self.scan("someone.near")
        self.assertLess(time.monotonic() - t0, 1.5)
        self.assertEqual(r.status_code, 504, r.text)
        self.assertIn("FastNEAR did not answer within 1 s", r.json()["detail"])

    def test_fastnear_body_of_the_wrong_shape_is_502_without_raw_data(self):
        cases = [{"/account": b'{"account_txs":"JUNKJUNK"}'},
                 {"/account": b'{"account_txs":[{"transaction_hash":"JUNKJUNK"}]}'},
                 {"/account": ONE_ROW, "/transactions": b'{"transactions":"JUNKJUNK"}'},
                 {"/account": ONE_ROW, "/transactions": b'{"transactions":[null]}'}]
        for bodies in cases:
            with self.subTest(bodies):
                intents.clear_cache()
                intents.TRANSPORT = Answer(bodies)
                r = self.scan("someone.near")
                self.assertEqual(r.status_code, 502, r.text)
                detail = r.json()["detail"]
                self.assertIn("FastNEAR", detail)
                self.assertNotIn("JUNK", detail)
                self.assertLessEqual(len(detail), 300)

    def test_unreadable_scan_is_not_cached(self):
        intents.TRANSPORT = Answer({"/account": b"[]"})
        self.assertEqual(self.scan("someone.near").status_code, 502)
        intents.TRANSPORT = answer = Answer({"/account": EMPTY_INDEX})
        self.assertEqual(self.scan("someone.near").status_code, 200)
        self.assertEqual(answer.calls, ["/account"])

    def test_missing_model_manifest_is_503(self):
        saved = intents.MODEL_JSON
        self.addCleanup(setattr, intents, "MODEL_JSON", saved)
        intents.MODEL_JSON = MODEL.with_name("missing_intents_model.json")
        intents.TRANSPORT = Answer({"/account": EMPTY_INDEX})
        r = self.scan("someone.near")
        self.assertEqual(r.status_code, 503, r.text)
        self.assertIn("intents model unavailable", r.json()["detail"])


if __name__ == "__main__":
    unittest.main()
