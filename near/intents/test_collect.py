"""Collector tests. Fixtures under fixtures/ are real FastNEAR responses recorded on 2026-11-14
(account_first_page.json: the first 3 rows of the intents.near account index; transactions_4.json: a POA ft_deposit,
a failing execute_intents, a direct ft_withdraw and a second ft_deposit) plus the scouting's attacker_accounts.json."""
import gzip
import json
import random
import tempfile
import unittest
from pathlib import Path

from near.intents import collect
from near.intents.fastnear import FastNear, Pacer, Refused, backoff_delay, dedupe_txs, unique

FIX = Path(__file__).parent / "fixtures"
TXS = {t["transaction"]["hash"]: t for t in json.loads((FIX / "transactions_4.json").read_text())["transactions"]}
DEPOSIT = TXS["CVU6zKhNDHKMD6dfFiiQfpE5Sts1pMf456EnkD34H5C3"]
EXECUTE_FAIL = TXS["EUL92J9QvtLCp5hTnj8jfak9rxA4mt1938duvfhGr4QH"]
WITHDRAW = TXS["En518qd2BbsfKC3uNE9PsaTpirV6MDdq4E7bS5wh2gz3"]
ACCOUNT_PAGE = json.loads((FIX / "account_first_page.json").read_text())


class FakeClock:
    """Deterministic time source: sleep advances the clock and records the duration."""

    def __init__(self):
        self.t = 1000.0
        self.slept: list[float] = []

    def clock(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.t += s


class Replay:
    """Transport that replays a fixed list of (status, headers, body) responses and records request bodies."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, path, body):
        self.calls.append((path, body))
        return self.responses.pop(0)


def ok(obj) -> tuple[int, dict, bytes]:
    return 200, {}, json.dumps(obj).encode()


TOO_MANY = (429, {}, b"Too Many Requests")


class PacingTest(unittest.TestCase):
    def test_pacer_spaces_requests(self):
        c = FakeClock()
        p = Pacer(1.0, c.clock, c.sleep)
        p.wait()
        c.t += 0.25
        p.wait()
        p.wait()
        self.assertEqual(c.slept, [0.75, 1.0])

    def test_penalize_pushes_next_request(self):
        c = FakeClock()
        p = Pacer(1.0, c.clock, c.sleep)
        p.wait()
        p.penalize(10)
        p.wait()
        self.assertEqual(c.slept, [10.0])

    def test_backoff_grows_and_caps(self):
        self.assertEqual([backoff_delay(i) for i in range(6)], [5, 10, 20, 40, 80, 120])

    def test_retries_after_429_then_succeeds(self):
        c = FakeClock()
        t = Replay([TOO_MANY, (429, {"Retry-After": "3"}, b""), ok(ACCOUNT_PAGE)])
        fn = FastNear(t, Pacer(1.0, c.clock, c.sleep))
        d = fn.account_page("intents.near", desc=False, limit=3)
        self.assertEqual(d["txs_count"], ACCOUNT_PAGE["txs_count"])
        self.assertEqual(fn.stats["http_429"], 2)
        self.assertEqual(fn.stats["requests"], 3)
        self.assertEqual(c.slept, [5.0, 3.0])  # exponential first, then the server's Retry-After
        self.assertEqual(t.calls[0], ("/account", {"account_id": "intents.near", "limit": 3, "desc": False}))

    def test_refuses_after_sustained_429(self):
        c = FakeClock()
        fn = FastNear(Replay([TOO_MANY] * 20), Pacer(1.0, c.clock, c.sleep), max_tries=20, refuse_after=60)
        with self.assertRaises(Refused):
            fn.post("/account", {"account_id": "intents.near"})
        self.assertLess(fn.stats["requests"], 6)

    def test_client_error_is_not_retried(self):
        c = FakeClock()
        fn = FastNear(Replay([(400, {}, b"bad request")]), Pacer(1.0, c.clock, c.sleep))
        with self.assertRaisesRegex(RuntimeError, "HTTP 400"):
            fn.post("/transactions", {"tx_hashes": ["x"]})


class DedupeTest(unittest.TestCase):
    def test_unique_keeps_order(self):
        self.assertEqual(unique(["b", "a", "b", "c", "a"]), ["b", "a", "c"])

    def test_dedupe_txs_drops_none_repeats_and_seen(self):
        seen = {WITHDRAW["transaction"]["hash"]}
        out = dedupe_txs([DEPOSIT, None, DEPOSIT, WITHDRAW, EXECUTE_FAIL], seen)
        self.assertEqual([collect.tx_hash(t) for t in out], [collect.tx_hash(DEPOSIT), collect.tx_hash(EXECUTE_FAIL)])
        self.assertIn(collect.tx_hash(DEPOSIT), seen)

    def test_transactions_batches_by_20_and_dedupes(self):
        c = FakeClock()
        hashes = [f"h{i}" for i in range(25)] + ["h0"]
        t = Replay([ok({"transactions": [DEPOSIT, DEPOSIT, None]}), ok({"transactions": [DEPOSIT, WITHDRAW]})])
        fn = FastNear(t, Pacer(1.0, c.clock, c.sleep))
        out = fn.transactions(hashes)
        self.assertEqual([len(b["tx_hashes"]) for _, b in t.calls], [20, 5])
        self.assertEqual([collect.tx_hash(x) for x in out], [collect.tx_hash(DEPOSIT), collect.tx_hash(WITHDRAW)])

    def test_page_hashes_excludes_known_and_samples(self):
        rows = ACCOUNT_PAGE["account_txs"] + ACCOUNT_PAGE["account_txs"][:1]
        known = {rows[1]["transaction_hash"]}
        got = collect.page_hashes(rows, known, k=10, rng=random.Random(0))
        self.assertEqual(sorted(got), sorted([rows[0]["transaction_hash"], rows[2]["transaction_hash"]]))
        self.assertEqual(len(collect.page_hashes(rows, set(), k=1, rng=random.Random(0))), 1)


class WindowTest(unittest.TestCase):
    def test_month_starts(self):
        self.assertEqual(collect.month_starts("2024-11", "2025-02"), ["2024-11", "2024-12", "2025-01", "2025-02"])

    def test_windows_interpolate_month_boundaries(self):
        # 1 block per second from 2024-11-01T00:00Z (1730419200), height 100.
        t0 = 1730419200
        probes = [(100 + s, (t0 + s) * 10**9) for s in range(0, 120 * 86400, 86400 * 7)]
        last_h, last_ts = probes[-1]
        ws = collect.month_windows(probes, first_height=100, last_height=last_h)
        self.assertEqual([w["window"] for w in ws], ["2024-11", "2024-12", "2025-01", "2025-02"])
        self.assertEqual(ws[0]["from_height"], 100)
        self.assertEqual(ws[1]["from_height"], 100 + 30 * 86400)   # 2024-12-01
        self.assertEqual(ws[2]["from_height"], 100 + 61 * 86400)   # 2025-01-01
        for a, b in zip(ws, ws[1:]):
            self.assertEqual(a["to_height"], b["from_height"] - 1)
        self.assertEqual(ws[-1]["to_height"], last_h)

    def test_tx_month_from_execution_outcome(self):
        self.assertEqual(collect.tx_month(DEPOSIT), "2026-11")


class MetaTest(unittest.TestCase):
    def test_label_for_role(self):
        self.assertEqual(collect.label_for_role("exploit"), 1)
        self.assertEqual(collect.label_for_role("attempt"), 1)
        self.assertEqual(collect.label_for_role("team_regression_test"), 0)
        for r in ("setup", "cashout", "setup_funding_via_intents"):
            self.assertEqual(collect.label_for_role(r), "cluster")
        with self.assertRaises(ValueError):
            collect.label_for_role("unknown")

    def test_attach_meta_keeps_tx_and_adds_meta(self):
        rec = collect.attach_meta(DEPOSIT, source="fastnear", label=0, month="2026-11", window="2026-11")
        self.assertEqual(rec["transaction"], DEPOSIT["transaction"])
        self.assertNotIn("_meta", DEPOSIT)
        m = rec["_meta"]
        self.assertEqual((m["label"], m["month"], m["window"], m["source"]), (0, "2026-11", "2026-11", "fastnear"))
        self.assertIsNone(m["campaign"])
        self.assertIsNone(m["role"])
        self.assertRegex(m["fetched_at"], r"^\d{4}-\d\d-\d\dT")

    def test_labelled_meta_keeps_role_and_incident_verbatim(self):
        row = {"tx_hash": "x", "role": "setup_funding_via_intents",
               "incident": "2026-04-16 Rhea Finance margin exploit"}
        m = collect.attach_meta(DEPOSIT, **collect.labelled_meta(row, "fastnear"))["_meta"]
        self.assertEqual((m["label"], m["role"], m["campaign"]),
                         ("cluster", "setup_funding_via_intents", "2026-04-16 Rhea Finance margin exploit"))


class AttackerTest(unittest.TestCase):
    IDS = collect.attacker_ids(json.loads((FIX / "attacker_accounts.json").read_text()))

    def test_attacker_ids_parsed_and_team_excluded(self):
        self.assertIn("20e6bfe4685d99004fc2095d3a0fc6158cd810ce8f801196141e183ed6e19d65", self.IDS)
        self.assertIn("test1779579480756.near", self.IDS)
        self.assertIn("poornode5201.near", self.IDS)
        self.assertIn("b9ad4da1d9d822ef573adbc8c554de21f1dcaea3988cada6537758a33f9cfb39", self.IDS)
        self.assertNotIn("e81ff331aeab3cb54f3e64e4b770a0541df6a0fe63c43c27e81be911b506459b", self.IDS)
        self.assertNotIn("defuse-ops.near", self.IDS)
        self.assertNotIn("intents.near", self.IDS)

    def test_mentions_any_reads_base64_args(self):
        inner = "5cdaee04aeec7abf076fd197411ffab6b08cf7aaefba14b57f6fc5fbececc3c8"  # only inside base64 args
        self.assertNotIn(inner, json.dumps(EXECUTE_FAIL))
        self.assertTrue(collect.mentions_any(EXECUTE_FAIL, {inner}))
        self.assertFalse(collect.mentions_any(EXECUTE_FAIL, self.IDS))
        self.assertTrue(collect.mentions_any(WITHDRAW, {"prl.omft.near"}))


class LabelledSignerTest(unittest.TestCase):
    SETUP = "f59f52d31ed269ade019a55ac4046a4e2fd7e0a3d6e585c4afc4777aab71f834"  # setup in both May campaigns
    TEAM = "e81ff331aeab3cb54f3e64e4b770a0541df6a0fe63c43c27e81be911b506459b"
    ROWS = [{"signer": SETUP, "role": "setup"},
            {"signer": "test1779579480756.near", "role": "attempt"},
            {"signer": "873518f0f5cf120d7a8e2a416337bba16d7ae622e91f7da3862f07e89dc2ba9e", "role": "cashout"},
            {"signer": TEAM, "role": "team_regression_test"},
            {"signer": "intents.near", "role": "setup_funding_via_intents"},
            {"signer": "meteor-relayer.near", "role": "setup"},
            {"signer": "team.herewallet.near", "role": "setup"}]

    def test_signers_of_non_team_rows_minus_infrastructure(self):
        self.assertEqual(collect.labelled_signers(self.ROWS),
                         {self.SETUP, "test1779579480756.near",
                          "873518f0f5cf120d7a8e2a416337bba16d7ae622e91f7da3862f07e89dc2ba9e"})

    def test_exclusion_reason(self):
        signers = collect.labelled_signers(self.ROWS) | {WITHDRAW["transaction"]["signer_id"]}
        self.assertEqual(collect.exclusion_reason(WITHDRAW, AttackerTest.IDS, signers), "labelled_signer")
        self.assertEqual(collect.exclusion_reason(WITHDRAW, {"prl.omft.near"}, set()), "attacker")
        self.assertIsNone(collect.exclusion_reason(DEPOSIT, AttackerTest.IDS, signers))


class InputPathTest(unittest.TestCase):
    def test_defaults_read_the_files_shipped_in_the_repo_and_archive(self):
        a = collect.parser().parse_args(["normals"])
        self.assertEqual(a.labels, collect.DATA / "all_labelled_txs.jsonl")
        self.assertEqual(a.attackers, FIX.resolve() / "attacker_accounts.json")
        self.assertIsNone(a.scout)

    def test_label_files_can_be_overridden(self):
        a = collect.parser().parse_args(["--labels", "l.jsonl", "--attackers", "a.json", "normals"])
        self.assertEqual((a.labels, a.attackers), (Path("l.jsonl"), Path("a.json")))

    def test_seed_txs_is_empty_without_a_scouting_directory(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(list(collect.seed_txs(None)), [])
            self.assertEqual(list(collect.seed_txs(Path(d) / "absent")), [])

    def test_seed_txs_reads_the_bulk_access_layout(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("exploit_23", "month_2025_01"):
                p = Path(d) / "bulk-access" / "data" / name / "txs.jsonl"
                p.parent.mkdir(parents=True)
                p.write_text(json.dumps(DEPOSIT) + "\n\n")
            self.assertEqual(list(collect.seed_txs(Path(d), skip_dirs=("exploit_23",))), [("month_2025_01", DEPOSIT)])

    def test_load_labels_skips_blank_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "labels.jsonl"
            p.write_text('{"tx_hash": "a", "signer": "x", "role": "setup"}\n\n{"tx_hash": "b", "signer": "y", '
                         '"role": "attempt"}\n')
            self.assertEqual([r["tx_hash"] for r in collect.load_labels(p)], ["a", "b"])


class FlowTest(unittest.TestCase):
    def test_flow_types(self):
        self.assertEqual(collect.flow_type(DEPOSIT), "deposit")
        self.assertEqual(collect.flow_type(EXECUTE_FAIL), "execute_intents")
        self.assertEqual(collect.flow_type(WITHDRAW), "withdrawal")

    def test_failure_comes_from_receipts_not_tx_status(self):
        self.assertIn("SuccessReceiptId", EXECUTE_FAIL["execution_outcome"]["outcome"]["status"])
        self.assertTrue(collect.any_receipt_failed(EXECUTE_FAIL))
        self.assertFalse(collect.any_receipt_failed(DEPOSIT))


class StoreTest(unittest.TestCase):
    def test_append_and_read_back(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.jsonl.gz"
            collect.append_jsonl_gz(p, [{"a": 1}])
            collect.append_jsonl_gz(p, [{"a": 2}, {"a": 3}])
            self.assertEqual([r["a"] for r in collect.load_jsonl_gz(p)], [1, 2, 3])

    def test_truncated_tail_is_repaired(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.jsonl.gz"
            collect.append_jsonl_gz(p, [{"a": 1}])
            good = p.stat().st_size
            collect.append_jsonl_gz(p, [{"a": i} for i in range(2, 200)])
            with open(p, "r+b") as f:
                f.truncate(good + 40)  # a killed writer leaves a partial gzip member
            self.assertEqual([r["a"] for r in collect.load_jsonl_gz(p)], [1])
            self.assertEqual(collect.repair_jsonl_gz(p), good)
            self.assertEqual(p.stat().st_size, good)
            collect.append_jsonl_gz(p, [{"a": 9}])
            self.assertEqual([r["a"] for r in collect.load_jsonl_gz(p)], [1, 9])
            with gzip.open(p, "rt") as f:
                self.assertEqual(len(f.readlines()), 2)

    def test_missing_file_reads_empty(self):
        self.assertEqual(collect.load_jsonl_gz(Path("/nonexistent/x.jsonl.gz")), [])


if __name__ == "__main__":
    unittest.main()
