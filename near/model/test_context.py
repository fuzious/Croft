import os
import re
import subprocess
import tempfile
import unittest

import numpy as np

from near.analyzer import extract_functions
from near.model import context as cx

CARGO = """[package]
name = "vault"
[dependencies]
near-sdk = "4.1.1"
[profile.release]
overflow-checks = true
"""
LIB = """use near_sdk::{env, near_bindgen, AccountId, Promise};

#[near_bindgen]
pub struct Vault { owner_id: AccountId, total: u128 }

#[near_bindgen]
impl Vault {
    fn assert_owner(&self) {
        assert_eq!(env::predecessor_account_id(), self.owner_id, "owner only");
    }

    pub fn set_fee(&mut self, fee: u128) {
        self.assert_owner();
        self.total = fee;
    }

    pub fn set_limit(&mut self, limit: u128) {
        self.total = limit;
        self.total += 1;
    }

    pub fn withdraw(&mut self, amount: u128) -> Promise {
        self.total -= amount;
        Promise::new(env::predecessor_account_id()).transfer(amount)
            .then(Self::ext(env::current_account_id()).on_withdraw(amount))
    }

    pub fn on_withdraw(&mut self, amount: u128) {
        self.total += amount;
        self.total += 0;
    }
}
"""
HELPER = """pub fn helper_math(a: u128, b: u128) -> u128 {
    let c = a * b;
    c / 2
}
"""


def fns_of(src, path):
    return {f["fn"]: dict(f, path=path) for f in extract_functions(src, path)}


class ScopeTest(unittest.TestCase):
    KEYS = ["Cargo.toml", "contracts/a/Cargo.toml", "contracts/a/src/lib.rs", "contracts/a/src/x.rs",
            "contracts/a/tests/it.rs", "contracts/b/Cargo.toml", "contracts/b/src/lib.rs", "README.md"]

    def test_file_scope_is_own_file_and_ancestor_manifests(self):
        self.assertEqual(cx.scope_paths(self.KEYS, "contracts/a/src/x.rs"),
                         ["contracts/a/src/x.rs", "contracts/a/Cargo.toml", "Cargo.toml"])

    def test_crate_scope_uses_nearest_crate(self):
        self.assertEqual(cx.crate_root(self.KEYS, "contracts/a/src/x.rs"), "contracts/a")
        self.assertEqual(cx.scope_paths(self.KEYS, "contracts/a/src/x.rs", crate=True),
                         ["contracts/a/src/x.rs", "contracts/a/src/lib.rs", "contracts/a/Cargo.toml", "Cargo.toml"])

    def test_no_manifest_means_every_rs_file_in_crate_scope(self):
        self.assertIsNone(cx.crate_root(["a.rs", "b/c.rs"], "a.rs"))
        self.assertEqual(cx.scope_paths(["b/c.rs", "a.rs"], "a.rs", crate=True), ["a.rs", "b/c.rs"])

    def test_detector_names_match_the_analyzer(self):
        with open("near/analyzer/detectors.py") as f:
            emitted = set(re.findall(r'_hit\(c, "(\w+)"', f.read()))
        self.assertEqual(emitted, set(cx.DETECTOR_NAMES))


class FeatureTest(unittest.TestCase):
    def setUp(self):
        self.files = {"Cargo.toml": CARGO, "src/lib.rs": LIB, "src/math.rs": HELPER}
        self.fns = fns_of(LIB, "src/lib.rs")

    def ctx(self, name, files=None):
        return cx.row_context(self.fns[name], "src/lib.rs", self.files if files is None else files)["context"]

    def test_crate_facts(self):
        c = self.ctx("set_fee")
        self.assertEqual(c["ctx_overflow_checks"], 1.0)
        self.assertAlmostEqual(c["ctx_sdk_version"], 4.01)
        self.assertEqual(c["ctx_owner_field"], 1.0)

    def test_owner_helper_and_unchecked_sibling(self):
        fee, limit = self.ctx("set_fee"), self.ctx("set_limit")
        self.assertEqual(fee["ctx_n_auth_helpers"], 1.0)
        self.assertEqual(fee["ctx_calls_auth_helper"], 1.0)
        self.assertEqual(fee["ctx_owner_unchecked_mut_entry"], 0.0)
        self.assertEqual(limit["ctx_calls_auth_helper"], 0.0)
        self.assertEqual(limit["ctx_owner_unchecked_mut_entry"], 1.0)
        self.assertGreater(limit["ctx_incons_similar_auth"], 0.0)  # set_fee (similar name) checks, set_limit doesn't

    def test_callback_resolution(self):
        w, cb = self.ctx("withdraw"), self.ctx("on_withdraw")
        self.assertEqual(w["ctx_cb_scheduled"], 1.0)
        self.assertEqual(w["ctx_cb_resolved"], 1.0)
        self.assertEqual(w["ctx_cb_unprivate"], 1.0)
        self.assertEqual(w["ctx_cb_no_result"], 1.0)
        self.assertEqual(cb["ctx_is_cb_target"], 1.0)
        self.assertEqual(cb["ctx_cb_target_unprotected"], 1.0)

    def test_private_callback_is_not_unprivate(self):
        lib = LIB.replace("    pub fn on_withdraw", "    #[private]\n    pub fn on_withdraw")
        files = dict(self.files, **{"src/lib.rs": lib})
        self.fns = fns_of(lib, "src/lib.rs")
        self.assertEqual(self.ctx("withdraw", files)["ctx_cb_unprivate"], 0.0)
        self.assertEqual(self.ctx("on_withdraw", files)["ctx_cb_target_unprotected"], 0.0)

    def test_callers_of_internal_helper(self):
        self.assertEqual(self.ctx("assert_owner")["ctx_n_callers"], np.log1p(1))

    def test_function_alone_when_file_missing(self):
        out = cx.row_context(self.fns["set_limit"], "src/lib.rs", None)
        self.assertFalse(out["available"])
        self.assertEqual(out["context"]["ctx_overflow_checks"], -1.0)
        self.assertEqual(out["context"]["ctx_n_mut_entries"], 0.0)

    def test_detector_counts_per_detector(self):
        d = cx.row_context(self.fns["on_withdraw"], "src/lib.rs", self.files)["detectors"]
        self.assertEqual(d["det_non_private_callback"], 1.0)
        self.assertEqual(sum(d.values()), sum(v for k, v in d.items() if k.startswith("det_")))


class GitParityTest(unittest.TestCase):
    """Training reads the scope files from a clone at a commit; inference gets a files dict. Same features."""

    def test_training_and_inference_paths_agree(self):
        from near.model import train_classic_v2 as t2
        with tempfile.TemporaryDirectory() as d:
            for p, s in {"Cargo.toml": CARGO, "src/lib.rs": LIB, "src/math.rs": HELPER, "README.md": "x"}.items():
                os.makedirs(os.path.join(d, os.path.dirname(p)), exist_ok=True)
                with open(os.path.join(d, p), "w") as f:
                    f.write(s)
            env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
                       GIT_COMMITTER_EMAIL="t@t")
            for cmd in (["init", "-q"], ["add", "."], ["-c", "commit.gpgsign=false", "commit", "-q", "-m", "x"]):
                subprocess.run(["git", "-C", d, *cmd], check=True, env=env, capture_output=True)
            commit = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True,
                                    check=True).stdout.strip()
            rows = [dict(f, commit=commit, fetched_from=os.path.basename(d)) for f in fns_of(LIB, "src/lib.rs").values()]
            rows += [dict(f, commit=commit, fetched_from=os.path.basename(d)) for f in fns_of(HELPER, "src/math.rs").values()]
            rows.append(dict(rows[0], commit="0" * 40))  # unknown commit -> function alone
            jobs = {}
            for i, r in enumerate(rows):
                jobs.setdefault(r["commit"], []).append((i, cx.fn_record(r), r["path"]))
            res = {}
            for c, items in jobs.items():
                out, stats = t2._ctx_job((d, c, items))
                res.update({i: (a, det, x) for i, a, det, x, _ in out})
            files = {"Cargo.toml": CARGO, "src/lib.rs": LIB, "src/math.rs": HELPER, "README.md": "x"}
            inf = t2.matrices_for_source(files, rows[:-1])
            for i in range(len(rows) - 1):
                a, det, x = res[i]
                np.testing.assert_allclose(t2._slog(np.array([a]))[0], inf["A1"][i], rtol=1e-6)
                np.testing.assert_allclose(t2._slog(np.array([det]))[0], inf["D"][i], rtol=1e-6)
                np.testing.assert_allclose(np.array(x, np.float32), inf["X"][i], rtol=1e-6)
            alone = res[len(rows) - 1][2]
            self.assertEqual(alone[cx.CONTEXT_KEYS.index("ctx_overflow_checks")], -1.0)


if __name__ == "__main__":
    unittest.main()
