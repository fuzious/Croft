"""Unit tests for near.intents.head (domain check, head thresholds, adoption rule) on small numpy arrays."""
import math
import unittest

import numpy as np

from near.intents import head as hd
from near.intents import model as md


def _domain_data(n_syn=300, n_real=600, d=6, leak_cols=(), shift=4.0, seed=0):
    rng = np.random.default_rng(seed)
    Xs = rng.normal(size=(n_syn, d)).astype(np.float32)
    Xr = rng.normal(size=(n_real, d)).astype(np.float32)
    for j in leak_cols:
        Xs[:, j] += shift
    gs = np.array([f"fam{i % 6}" for i in range(n_syn)], dtype=object)
    gr = np.array([f"2025-{1 + i % 10:02d}" for i in range(n_real)], dtype=object)
    return Xs, gs, Xr, gr, [f"f{j}" for j in range(d)]


class FlowMatchedSample(unittest.TestCase):
    def test_matches_the_synthetic_flow_mix_with_one_common_ratio(self):
        syn = np.array(["deposit"] * 10 + ["withdrawal"] * 5, dtype=object)
        real = np.array(["deposit"] * 100 + ["withdrawal"] * 8 + ["other"] * 50, dtype=object)
        idx = hd.flow_matched_sample(real, syn, max_ratio=3, seed=0)
        got = {f: int((real[idx] == f).sum()) for f in ("deposit", "withdrawal", "other")}
        # withdrawal caps the ratio at 8/5 = 1.6, so deposit gets floor(1.6 * 10) = 16 and other none
        self.assertEqual(got, {"deposit": 16, "withdrawal": 8, "other": 0})
        self.assertEqual(len(set(idx.tolist())), len(idx))


class DomainCheck(unittest.TestCase):
    def test_same_distribution_is_near_chance(self):
        Xs, gs, Xr, gr, keys = _domain_data()
        auc = hd.domain_auc(np.vstack([Xs, Xr]), np.r_[np.ones(len(Xs)), np.zeros(len(Xr))], np.r_[gs, gr])
        self.assertLess(auc, 0.65)

    def test_drops_the_leaking_feature_and_passes(self):
        Xs, gs, Xr, gr, keys = _domain_data(leak_cols=(2,))
        rep = hd.domain_check(Xs, gs, Xr, gr, keys)
        self.assertGreater(rep["auc_all_features"], hd.DOMAIN_AUC_MAX)
        self.assertTrue(rep["passed"])
        self.assertEqual(rep["dropped"], ["f2"])
        self.assertNotIn("f2", rep["kept"])
        self.assertLessEqual(rep["steps"][-1]["auc"], hd.DOMAIN_AUC_MAX)

    def test_fails_when_more_than_the_drop_budget_leaks(self):
        Xs, gs, Xr, gr, keys = _domain_data(leak_cols=(0, 1, 2, 3, 4, 5))
        rep = hd.domain_check(Xs, gs, Xr, gr, keys)
        self.assertFalse(rep["passed"])
        self.assertLessEqual(len(rep["dropped"]), math.floor(hd.MAX_DROP_FRAC * len(keys)))
        self.assertGreater(rep["steps"][-1]["auc"], hd.DOMAIN_AUC_MAX)


class HeadThresholds(unittest.TestCase):
    def test_combined_calibration_alerts_stay_within_budget(self):
        rng = np.random.default_rng(1)
        p = rng.random(20_000)
        base = np.full(20_000, "low", dtype=object)
        base[:5] = "medium"
        base[5] = "high"
        thr = hd.head_thresholds(p, base)
        lab = hd.combine_labels(base, p, thr)
        self.assertLessEqual(int((lab == "high").sum()), math.floor(md.HIGH_RATE * 20_000))
        self.assertLessEqual(int((lab != "low").sum()), math.floor(md.MEDIUM_RATE * 20_000))
        self.assertLessEqual(thr["high"], 1.0 + 1e-12)

    def test_combine_labels_takes_the_max(self):
        base = np.array(["low", "medium", "low", "high"], dtype=object)
        p = np.array([0.95, 0.1, 0.5, 0.0])
        lab = hd.combine_labels(base, p, {"high": 0.9, "medium": 0.4})
        self.assertEqual(lab.tolist(), ["high", "medium", "medium", "high"])


class HeadFit(unittest.TestCase):
    def test_positive_mask_counts_only_exploits_and_attempts(self):
        roles = np.array(["exploit", "attempt", "setup", "cashout", "team_regression_test", None], dtype=object)
        self.assertEqual(hd.positive_mask(roles).tolist(), [True, True, False, False, False, False])

    def test_fit_head_separates_shifted_positives(self):
        rng = np.random.default_rng(2)
        Xp = rng.normal(3, 1, size=(200, 4))
        Xn = rng.normal(0, 1, size=(2000, 4))
        clf = hd.fit_head(Xp, Xn)
        p = clf.predict_proba(np.vstack([Xp[:20], Xn[:20]]))[:, 1]
        self.assertGreater(p[:20].min(), p[20:].max() - 0.5)
        self.assertGreater(p[:20].mean(), 0.9)
        self.assertLess(p[20:].mean(), 0.1)


class AdoptionRule(unittest.TestCase):
    def test_adopts_only_with_enough_gain_and_no_extra_false_alarms_beyond_budget(self):
        ok = hd.decide(pos_base=100, pos_head=110, test_fa_added_med=3, test_fa_added_high=0, n_test=12_463)
        self.assertTrue(ok["adopt"])
        few = hd.decide(pos_base=100, pos_head=104, test_fa_added_med=0, test_fa_added_high=0, n_test=12_463)
        self.assertFalse(few["adopt"])
        noisy = hd.decide(pos_base=100, pos_head=150, test_fa_added_med=13, test_fa_added_high=0, n_test=12_463)
        self.assertFalse(noisy["adopt"])
        loud = hd.decide(pos_base=100, pos_head=150, test_fa_added_med=2, test_fa_added_high=2, n_test=12_463)
        self.assertFalse(loud["adopt"])


if __name__ == "__main__":
    unittest.main()
