"""Mechanism grouping for the 437 attack-labelled Intents transactions."""
import unittest

from near.intents.audit.mechanism_table import DATA, mechanism, summary, table


def failed(message):
    return {"receipts": [{"execution_outcome": {"outcome": {"status": {"Failure": {"ExecutionError": message}}}}}]}


class MechanismTests(unittest.TestCase):
    def test_entry_method_and_rejection_reason_choose_the_mechanism(self):
        may = "2026-05-20 fuzzer"
        cases = [
            ({"methods": ["mt_on_transfer"], "incident": may}, {}, "M3"),
            ({"methods": ["ft_resolve_deposit"], "incident": may}, {}, "M4"),
            ({"methods": ["execute_intents"], "incident": may}, {}, "M6d"),
            ({"methods": ["execute_intents"], "incident": may}, failed("invalid signature"), "M6a"),
            ({"methods": ["execute_intents"], "incident": may}, failed("insufficient balance or overflow"), "M6b"),
            ({"methods": ["execute_intents"], "incident": may}, failed("failed to deserialize"), "M6c"),
            ({"methods": ["ft_transfer_call"], "incident": "2026-04-03 actor"}, {}, "M2"),
            ({"methods": ["ft_transfer_call"], "incident": may}, {}, "M7"),
            ({"methods": [], "incident": "2026-10-01 exploit"}, {}, "M1"),
        ]
        for row, tx, code in cases:
            with self.subTest(code=code):
                self.assertEqual(mechanism(row, tx).split()[0], code)

    @unittest.skipUnless((DATA / "labelled.jsonl.gz").exists() and (DATA / "all_labelled_txs.jsonl").exists(),
                         "labelled data ships in archives/near_intents.zip")
    def test_recorded_split_reproduces_from_labelled_data(self):
        result = table(DATA / "all_labelled_txs.jsonl", DATA / "labelled.jsonl.gz")
        _, groups = summary(result["rows"])
        self.assertEqual(result["n"], 437)
        self.assertEqual([(g["medium_plus"], g["n"]) for g in groups], [(204, 204), (0, 194), (0, 39)])
        april = next(r for r in result["rows"] if r["mechanism"].startswith("M2"))
        self.assertEqual((april["n"], april["rules"]["callback_oog"]), (53, 8))


if __name__ == "__main__":
    unittest.main()
