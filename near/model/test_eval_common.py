import unittest

import numpy as np

from near.model import eval_common as ec


def row(i, label, source, group, **kw):
    r = {"id": f"r{i}", "label": label, "source": source, "group": group, "path": "src/lib.rs", "code": "fn f() {}",
         "is_public": True, "vuln_class": kw.pop("vuln_class", None), "severity": None, "pair_id": None}
    r.update(kw)
    return r


class WilsonTest(unittest.TestCase):
    def test_bounds(self):
        lo, hi = ec.wilson(5, 10)
        self.assertAlmostEqual(lo, 0.2366, places=3)
        self.assertAlmostEqual(hi, 0.7634, places=3)
        self.assertTrue(all(np.isnan(ec.wilson(0, 0))))


class ThresholdTest(unittest.TestCase):
    def test_fpr_threshold_keeps_at_most_k_negatives(self):
        s = np.arange(100) / 100.0
        t = ec.threshold_at_fpr(s, np.ones(100, bool), 0.05)
        self.assertEqual(int((s >= t).sum()), 5)

    def test_ties_never_exceed_budget(self):
        s = np.array([0.9] * 10 + [0.1] * 90)
        t = ec.threshold_at_fpr(s, np.ones(100, bool), 0.05)
        self.assertEqual(int((s >= t).sum()), 0)

    def test_no_negatives_is_infinite(self):
        self.assertTrue(np.isinf(ec.threshold_at_fpr(np.array([0.5]), np.zeros(1, bool), 0.05)))


class ContractCodeTest(unittest.TestCase):
    def test_async_test_paths_and_offchain_dirs_are_not_contract_code(self):
        self.assertTrue(ec.is_contract_code(row(1, 0, "corpus", "g")))
        self.assertFalse(ec.is_contract_code(row(1, 0, "corpus", "g", code="pub async fn f() {}")))
        self.assertFalse(ec.is_contract_code(row(1, 0, "corpus", "g", path="tests/sandbox.rs")))
        self.assertFalse(ec.is_contract_code(row(1, 0, "corpus", "g", path="indexer/src/main.rs")))


class WeightsTest(unittest.TestCase):
    def test_real_weight_matches_mutation_weight_and_keeps_field_weight(self):
        rows = [row(i, 1, "mutation", "g") for i in range(10)]
        rows += [row(10, 1, "audit", "g", weight=1.0), row(11, 1, "audit", "g", weight=0.25),
                 row(12, 0, "fix_commit", "g", weight=1.0), row(13, 0, "corpus", "g")]
        w = ec.sample_weights(rows)
        self.assertAlmostEqual(w[10] + w[11], 10.0)
        self.assertAlmostEqual(w[10] / w[11], 4.0)
        self.assertAlmostEqual(w[12], w[10])
        self.assertEqual(w[13], 1.0)

    def test_info_weight_override_drops_info_rows_and_rescales(self):
        rows = [row(i, 1, "mutation", "g") for i in range(4)]
        rows += [row(4, 1, "audit", "g", weight=0.3, severity="info"), row(5, 1, "audit", "g", weight=1.0)]
        w = ec.sample_weights(rows, info_weight=0.0)
        self.assertEqual(w[4], 0.0)
        self.assertAlmostEqual(w[5], 4.0)


class FoldsTest(unittest.TestCase):
    def test_groups_never_cross_folds_and_cover_all_rows(self):
        groups = [f"g{i % 13}" for i in range(200)]
        folds = ec.group_folds(groups, 5, seed=1)
        seen = np.zeros(200, int)
        for tr, te in folds:
            self.assertFalse({groups[i] for i in tr} & {groups[i] for i in te})
            seen[te] += 1
        self.assertTrue((seen == 1).all())


def toy_rows():
    rows, i = [], 0
    for g in range(10):
        for _ in range(30):
            rows.append(row(i, 0, "corpus", f"g{g}", path=f"src/f{i % 3}.rs")); i += 1
        for _ in range(3):
            rows.append(row(i, 1, "mutation", f"g{g}", vuln_class="signer_auth")); i += 1
        if g % 2:  # real rows only in odd groups; even groups are clean for the contract-level number
            rows.append(row(i, 1, "audit", f"g{g}", vuln_class="logic_error", severity="high", pair_id=f"r{i + 1}"))
            rows.append(row(i + 1, 0, "audit", f"g{g}", pair_id=f"r{i}"))
            i += 2
    return rows


class NestedCVTest(unittest.TestCase):
    def test_perfect_scorer_gets_full_recall_without_corpus_alarms(self):
        rows = toy_rows()
        y = np.array([r["label"] for r in rows], float)
        calls = []

        def fit_predict(rows_, tr, te, inner):
            calls.append((len(tr), len(te), inner is None))
            self.assertFalse({rows_[i]["group"] for i in tr} & {rows_[i]["group"] for i in te})
            return {"scores": y[te], "params": {"c": 1}}

        out = ec.nested_group_cv(fit_predict, rows, outer=5, inner=3, seed=0, log=lambda *_: None)
        self.assertEqual(len(out["scores"]), len(rows))
        self.assertEqual(len(out["thresholds"]["block"]), 5)
        m = ec.metrics(rows, out["scores"], out["decisions"])
        self.assertEqual(m["roc_auc"], 1.0)
        self.assertEqual(m["block"]["recall_real"]["rate"], 1.0)
        self.assertEqual(m["block"]["fpr_corpus"]["k"], 0)
        self.assertEqual(m["block"]["recall_class_real"]["logic_error"]["n"], 5)
        self.assertEqual(m["pair_rank_acc"]["rate"], 1.0)
        self.assertEqual(m["block"]["contract_alarm_share"]["k"], 0)
        self.assertEqual(out["params"], [{"c": 1}] * 5)
        # threshold needs inner OOF scores: 5 outer fits + 5 * 3 inner fits when train_oof is not returned
        self.assertEqual(len(calls), 20)

    def test_train_oof_skips_inner_refits(self):
        rows = toy_rows()
        y = np.array([r["label"] for r in rows], float)
        n = []

        def fit_predict(rows_, tr, te, inner):
            n.append(1)
            return {"scores": y[te], "train_oof": y[tr]}

        ec.nested_group_cv(fit_predict, rows, outer=5, inner=3, seed=0, log=lambda *_: None)
        self.assertEqual(len(n), 5)

    def test_contract_alarm_uses_public_fns_of_clean_groups(self):
        rows = toy_rows()
        scores = np.zeros(len(rows))
        scores[0] = 1.0  # one corpus fn of g0, file src/f0.rs
        m = ec.metrics(rows, scores)
        files = m["block"]["contract_alarm_share"]
        self.assertEqual(files["n"], 15)  # 5 clean groups x 3 files
        self.assertEqual(files["k"], 1)

    def test_contract_recall_counts_files_holding_a_real_vulnerability(self):
        rows = toy_rows()
        scores = np.zeros(len(rows))
        vuln = [i for i, r in enumerate(rows) if r["source"] == "audit" and r["label"] == 1]
        for i in vuln:
            rows[i]["path"] = "src/f1.rs"
        scores[vuln[0]] = 1.0
        m = ec.metrics(rows, scores)
        self.assertEqual(m["block"]["contract_recall_real"]["n"], 5)
        self.assertEqual(m["block"]["contract_recall_real"]["k"], 1)

    def test_pair_rank_counts_ties_as_half(self):
        rows = toy_rows()
        r = ec.pair_rank(rows, np.zeros(len(rows)))
        self.assertEqual((r["k"], r["n"], r["rate"]), (2.5, 5, 0.5))


if __name__ == "__main__":
    unittest.main()
