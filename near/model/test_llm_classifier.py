import unittest
import importlib.util

import numpy as np

from near.model import llm_classifier as L


def row(i, label=0, source="corpus", pair=None, weight=None, verdict=None, group="g"):
    return {"id": f"r{i}", "code": "fn f() {}", "fn": "f", "label": label, "source": source, "pair_id": pair,
            "group": group, "path": "src/lib.rs", "severity": "high" if label else None, "weight": weight,
            "relabel_verdict": verdict, "vuln_class": "logic_error" if label else None}


class CharTok:
    """Stand-in tokenizer: one id per character."""

    def __call__(self, x, add_special_tokens=False):
        if isinstance(x, str):
            return {"input_ids": [ord(c) for c in x]}
        return {"input_ids": [[ord(c) for c in s] for s in x]}


class EncodeTest(unittest.TestCase):
    def test_suffix_always_last_and_length_capped(self):
        ids = L.encode(CharTok(), [("h", "x" * 100), ("h", "ab")], 40)
        suffix = [ord(c) for c in L.SUFFIX]
        self.assertEqual(len(ids[0]), 40)
        self.assertEqual(ids[0][-len(suffix):], suffix)
        self.assertEqual(ids[1], [ord(c) for c in "h\nab"] + suffix)

    def test_header_kept_whole_when_code_is_cut(self):
        ids = L.encode(CharTok(), [("head", "0123456789" * 10)], 30)
        self.assertEqual(ids[0][:5], [ord(c) for c in "head\n"])


class PairTest(unittest.TestCase):
    def setUp(self):
        self.rows = [row(0, 1, "fix_commit", "r1", 0.7), row(1, 0, "fix_commit", "r0"),
                     row(2, 1, "mutation", "r3"), row(3, 0, "mutation_original"), row(4, 1, "mutation", "r3"),
                     row(5), row(6, 1, "audit", "r7"), row(7, 1, "audit", "r6")]

    def test_edges_kinds_and_scope(self):
        e = L.pair_edges(self.rows, range(8))
        self.assertEqual(sorted(e), [(0, 1, "real"), (2, 3, "mutation"), (4, 3, "mutation")])
        self.assertEqual(L.pair_edges(self.rows, [0, 2, 3]), [(2, 3, "mutation")])

    def test_units_join_mutants_of_one_original(self):
        us = L.units(range(8), L.pair_edges(self.rows, range(8)))
        self.assertIn([2, 3, 4], us)
        self.assertIn([0, 1], us)
        self.assertEqual(sorted(i for u in us for i in u), list(range(8)))

    def test_batches_keep_units_whole_and_cover_every_row_once(self):
        rng = np.random.RandomState(0)
        lengths = rng.randint(10, 500, 300)
        us = [[3 * k, 3 * k + 1] for k in range(40)] + [[i] for i in range(120, 300)]
        bs = L.unit_batches(us, lengths, 2048, rng)
        flat = [i for b in bs for i in b]
        self.assertEqual(sorted(flat), sorted(i for u in us for i in u))
        where = {i: k for k, b in enumerate(bs) for i in b}
        self.assertTrue(all(where[a] == where[b] for a, b in us[:40]))
        for b in bs:
            L_b = -(-max(lengths[i] for i in b) // 64) * 64
            self.assertLessEqual(len(b) * L_b, 2048 + 64 * 2)

    def test_pairs_in_batch_and_weights(self):
        e = L.pair_edges(self.rows, range(8))
        w = L.pair_weights(self.rows, e, 5.0)
        self.assertAlmostEqual(w[(0, 1)], 3.5)
        self.assertEqual(w[(2, 3)], 1.0)
        by = {0: [1], 2: [3], 4: [3]}
        P, N, W = L.pairs_in_batch([3, 2, 0, 5], by, w)
        self.assertEqual((P, N, W), ([1], [0], [1.0]))


@unittest.skipUnless(importlib.util.find_spec("torch"), "optional LLM dependencies: uv sync --extra llm")
class LossTest(unittest.TestCase):
    def test_bce_only_without_pairs_and_margin_term(self):
        import torch
        import torch.nn.functional as F
        logit, y, w = torch.tensor([2.0, -1.0]), torch.tensor([1.0, 0.0]), torch.tensor([1.0, 3.0])
        bce = (F.binary_cross_entropy_with_logits(logit, y, reduction="none") * w).sum() / 2
        self.assertAlmostEqual(L.batch_loss(logit, y, w, [], [], [], 1.0, 1.0).item(), bce.item(), places=6)
        # gap 3 >= margin 1: no ranking loss; reversed pair: 1 - (-3) = 4, weight 2
        self.assertAlmostEqual(L.batch_loss(logit, y, w, [0], [1], [2.0], 1.0, 1.0).item(), bce.item(), places=6)
        self.assertAlmostEqual(L.batch_loss(logit, y, w, [1], [0], [2.0], 0.5, 1.0).item(), bce.item() + 0.5 * 8,
                               places=5)


class WeightTest(unittest.TestCase):
    def test_mean_one_and_corpus_upweighted_by_inverse_fraction(self):
        rows = [row(0, 1, "mutation"), row(1, 1, "audit", weight=0.6), row(2), row(3)]
        tr = np.arange(4)
        w = L.train_weights(rows, tr, 0.5)
        self.assertAlmostEqual(w.mean(), 1.0)
        self.assertAlmostEqual(w[2] / w[0], 2.0)


class MetricTest(unittest.TestCase):
    def test_mutation_pair_rank_and_real_detail(self):
        rows = [row(0, 1, "mutation", "r1"), row(1, 0, "mutation_original"), row(2, 1, "fix_commit", "r3",
                verdict="confirmed"), row(3, 0, "fix_commit", "r2")]
        s = np.array([0.9, 0.1, 0.2, 0.2])
        self.assertEqual(L.mutation_pair_rank(rows, s)["rate"], 1.0)
        d = L.real_pairs_detail(rows, s)
        self.assertEqual(d["all"]["rate"], 0.5)
        self.assertEqual(d["verdict=confirmed"]["n"], 1)
        self.assertEqual(d["source=fix_commit"]["mean_gap"], 0.0)

    def test_real_recall_split_by_verdict(self):
        rows = [row(0, 1, "audit", verdict="confirmed"), row(1, 1, "audit", verdict="plausible"),
                row(2, 1, "fix_commit"), row(3)]
        r = L.real_recall_split(rows, np.array([True, False, True, True]))
        self.assertEqual((r["verdict=confirmed"]["k"], r["verdict=plausible"]["k"], r["verdict=none"]["k"]), (1, 0, 1))
        self.assertEqual(r["source=audit"]["n"], 2)

    def test_oof_scores_use_each_folds_own_thresholds(self):
        import json
        import tempfile
        from pathlib import Path
        rows = [row(i) for i in range(4)]
        with tempfile.TemporaryDirectory() as d:
            for f, (ids, thr) in enumerate((([0, 1], 0.5), ([2, 3], 0.9))):
                fd = Path(d) / f"fold{f}"
                fd.mkdir()
                (fd / "fold.json").write_text(json.dumps({"thresholds": {"block": thr, "warn": thr}}))
                L.write_scores(fd / "scores_test.jsonl", rows, ids, [0.6, 0.4])
            s, fold, dec, folds = L.oof_scores(Path(d), rows)
        self.assertEqual(s.tolist(), [0.6, 0.4, 0.6, 0.4])
        self.assertEqual(fold.tolist(), [0, 0, 1, 1])
        self.assertEqual(dec["block"].tolist(), [True, False, False, False])
        self.assertEqual(len(folds), 2)

    def test_refuses_test_files(self):
        with self.assertRaises(SystemExit):
            L.load_train(path=L.DATA / "test_v1c.jsonl")


if __name__ == "__main__":
    unittest.main()
