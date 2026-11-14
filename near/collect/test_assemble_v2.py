import json
import tempfile
import unittest
from pathlib import Path

from near.collect import assemble, assemble_v2

A = "pub fn set_owner(&mut self, owner: AccountId) {\n    self.assert_owner();\n    self.owner = owner;\n}"
B = "pub fn get_owner(&self) -> AccountId {\n    let o = self.owner.clone();\n    o\n}"
LONG = ("pub fn withdraw(&mut self, amount: U128) -> Promise {\n    let account_id = env::predecessor_account_id();\n"
        "    let balance = self.balances.get(&account_id).unwrap_or(0);\n    assert!(balance >= amount.0, \"too much\");\n"
        "    self.balances.insert(&account_id, &(balance - amount.0));\n    ext_ft::ft_transfer(account_id.clone(), "
        "amount, None, self.token.clone(), 1, GAS)\n        .then(ext_self::on_withdraw(account_id, amount, "
        "env::current_account_id(), 0, GAS))\n}")


def row(id, code=A, label=0, source="corpus", group="g/a", vuln_class=None, pair_id=None, path="src/lib.rs", **kw):
    r = {"id": id, "code": code, "label": label, "source": source, "group": group, "vuln_class": vuln_class,
         "pair_id": pair_id, "fn": "f", "path": path, "severity": None, "weight": None, **kw}
    r.update({k: v for k, v in assemble.signatures(code).items() if k in ("norm_hash", "shape_hash", "n_tokens")})
    return r


def rl(id, verdict, split="train", pair_id=None, pair_verdict="n/a", vc=None, sev=None):
    return {"id": id, "split": split, "verdict": verdict, "vuln_class_corrected": vc, "severity_corrected": sev,
            "pair_id": pair_id, "pair_verdict": pair_verdict, "note": "n", "batch": "batch_0"}


def code(i):
    return f"pub fn f{i}(&mut self) {{\n    self.x{i} += {i};\n    self.y = {i};\n}}"


class ApplyRelabelsTest(unittest.TestCase):
    def setUp(self):
        self.rows = [
            row("v1", code(1), 1, "audit", vuln_class="logic_error", pair_id="f1", severity="low", weight=0.6),
            row("f1", code(2), 0, "audit", pair_id="v1", weight=0.6),
            row("v2", code(3), 1, "fix_commit", vuln_class="gas_dos", pair_id="f2", weight=1.0),
            row("f2", code(4), 0, "fix_commit", pair_id="v2", weight=1.0),
            row("v3", code(5), 1, "audit", vuln_class="logic_error", pair_id="f3", weight=1.0),
            row("f3", code(6), 0, "audit", pair_id="v3", weight=1.0),
            row("v4", code(7), 1, "audit", vuln_class="logic_error", weight=0.3, severity="info"),
            row("c4", code(7), 1, "corpus", vuln_class="logic_error", relabeled_from_real=True),
            row("n", code(8), 0, "corpus"),
        ]
        self.relabels = {"v1": rl("v1", "confirmed", pair_id="f1", pair_verdict="fixed", vc="unsafe_arithmetic",
                                  sev="high"),
                         "v2": rl("v2", "not_vulnerable", pair_id="f2", pair_verdict="fixed"),
                         "v3": rl("v3", "plausible", pair_id="f3", pair_verdict="unchanged_or_partial"),
                         "v4": rl("v4", "wrong_function")}

    def test_verdict_rules(self):
        out, removed, st = assemble_v2.apply_relabels(self.rows, self.relabels, "train")
        by = {r["id"]: r for r in out}
        self.assertEqual(sorted(by), ["f1", "n", "v1", "v3"])
        self.assertEqual(removed, {"v2": "relabel_not_vulnerable", "f2": "pair_of_removed_positive",
                                   "f3": "pair_unchanged_or_partial", "v4": "relabel_wrong_function",
                                   "c4": "copy_of_removed_positive"})
        self.assertEqual((by["v1"]["label"], by["v1"]["weight"], by["v1"]["vuln_class"], by["v1"]["severity"]),
                         (1, 1.0, "unsafe_arithmetic", "high"))
        self.assertEqual((by["v1"]["vuln_class_v1"], by["v1"]["severity_v1"], by["v1"]["weight_v1"]),
                         ("logic_error", "low", 0.6))
        self.assertEqual((by["v3"]["label"], by["v3"]["weight"], by["v3"]["vuln_class"]), (1, 0.6, "logic_error"))
        self.assertEqual((by["f1"]["label"], by["f1"]["weight"], by["f1"]["severity"]), (0, 1.0, "high"))
        self.assertEqual(by["n"], self.rows[-1])
        self.assertEqual(st["verdict_confirmed"], 1)
        self.assertEqual(st["vuln_class_corrected"], 1)

    def test_no_row_becomes_a_negative(self):
        out, _, _ = assemble_v2.apply_relabels(self.rows, self.relabels, "train")
        before = {r["id"]: r["label"] for r in self.rows}
        self.assertTrue(all(before[r["id"]] == r["label"] for r in out))

    def test_copy_follows_kept_positive_class(self):
        rows = [row("v", code(1), 1, "audit", vuln_class="logic_error", weight=1.0),
                row("c", code(1), 1, "mutation_original", vuln_class="logic_error", relabeled_from_real=True)]
        out, removed, _ = assemble_v2.apply_relabels(rows, {"v": rl("v", "confirmed", vc="gas_dos")}, "train")
        self.assertEqual(removed, {})
        self.assertEqual([r["vuln_class"] for r in out], ["gas_dos", "gas_dos"])

    def test_refuses_relabel_of_other_split_or_negative(self):
        with self.assertRaises(AssertionError):
            assemble_v2.apply_relabels(self.rows, {"v1": rl("v1", "confirmed", split="test")}, "train")
        with self.assertRaises(AssertionError):
            assemble_v2.apply_relabels(self.rows, {"n": rl("n", "confirmed")}, "train")


class LoadRelabelsTest(unittest.TestCase):
    def test_rejects_unknown_class_and_duplicate_id(self):
        with tempfile.TemporaryDirectory() as d:
            p, q = Path(d) / "batch_0.jsonl", Path(d) / "batch_1.jsonl"
            p.write_text(json.dumps(rl("a", "confirmed")) + "\n")
            self.assertEqual(assemble_v2.load_relabels([p])["a"]["batch"], "batch_0")
            q.write_text(json.dumps(rl("a", "plausible")) + "\n")
            with self.assertRaises(AssertionError):
                assemble_v2.load_relabels([p, q])
            q.write_text(json.dumps(rl("b", "confirmed", vc="reentrancy")) + "\n")
            with self.assertRaises(AssertionError):
                assemble_v2.load_relabels([q])


class ScreenNewRowsTest(unittest.TestCase):
    def setUp(self):
        self.test = [row("t1", LONG, 1, "audit", group="test/g", vuln_class="async_reentrancy"),
                     row("t2", B, 0, "corpus", group="test/h", repo_group="copy/h")]

    def test_drops_test_groups_copies_and_their_pairs(self):
        renamed = LONG.replace("withdraw", "take_out").replace("balances", "deposits")
        new = [row("a", code(1), 1, "fix_commit", group="test/g", pair_id="a0"),
               row("a0", code(2), 0, "fix_commit", group="test/g", pair_id="a"),
               row("b", B, 1, "fix_commit", group="new/x"),
               row("c", renamed, 1, "fix_commit", group="new/y", pair_id="c0"),
               row("c0", code(3), 0, "fix_commit", group="new/y", pair_id="c"),
               row("d", code(4), 1, "fix_commit", group="copy/h"),
               row("e", code(5), 1, "fix_commit", group="merged/z"),
               row("k", code(6), 1, "fix_commit", group="new/k")]
        kept, removed, sim = assemble_v2.screen_fix_commit_v2_rows(new, self.test, {"merged/z": "test/g"})
        self.assertEqual([r["id"] for r in kept], ["k"])
        self.assertEqual(removed["a"], "test_group")
        self.assertEqual(removed["b"], "norm_hash")
        self.assertIn(removed["c"], ("shape_hash", "idnorm_jaccard_0.8"))
        self.assertEqual(removed["c0"], "pair_partner_removed")
        self.assertEqual(removed["d"], "test_group")
        self.assertEqual(removed["e"], "test_group")
        self.assertEqual(sim["b"][0], 1.0)

    def test_drops_vendored_test_crate_and_split_audit_copies(self):
        new = [row("v", code(1), 1, "fix_commit", group="new/x", path="ref-farming/src/farmer.rs"),
               row("s", code(2), 1, "fix_commit", group="new/x"),
               row("k", code(3), 1, "fix_commit", group="new/x", path="contract/ref-farming/lib.rs")]
        leak = {assemble.signatures(code(2))["norm_hash"]}
        kept, removed, _ = assemble_v2.screen_fix_commit_v2_rows(new, self.test, {}, leak)
        self.assertEqual(removed, {"v": "vendored_test_crate", "s": "same_as_split_audit_drop"})
        self.assertEqual([r["id"] for r in kept], ["k"])

    def test_confidence_weights(self):
        out = assemble_v2.weigh_fix_commit_v2_rows([row("a", weight=0.6, confidence="high"), row("b", confidence="medium")])
        self.assertEqual([(r["weight"], r["weight_severity"]) for r in out], [(1.0, 0.6), (0.7, None)])


class TokensTest(unittest.TestCase):
    def test_idnorm_ignores_renaming_but_keeps_keywords(self):
        renamed = A.replace("owner", "admin")
        self.assertEqual(assemble_v2.idnorm_tokens(A), assemble_v2.idnorm_tokens(renamed))
        self.assertIn("self", assemble_v2.idnorm_tokens(A))
        self.assertNotEqual(assemble_v2.raw_tokens(A), assemble_v2.raw_tokens(renamed))


if __name__ == "__main__":
    unittest.main()
