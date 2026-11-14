import unittest

from near.collect import assemble

A = "pub fn set_owner(&mut self, owner: AccountId) {\n    self.assert_owner();\n    self.owner = owner;\n}"
A_RENAMED = "pub fn set_admin(&mut self, admin: AccountId) {\n    self.check_admin();\n    self.admin = admin;\n}"
A_COMMENTED = "/// Set owner.\npub fn set_owner(&mut self, owner: AccountId) {\n    // only owner\n    self.assert_owner();\n" \
              "    self.owner = owner;\n}"
B = "pub fn get_owner(&self) -> AccountId {\n    let o = self.owner.clone();\n    o\n}"


def row(id, code, label=0, source="corpus", group="g/a", vuln_class=None, date=None, pair_id=None):
    return {"id": id, "code": code, "label": label, "source": source, "group": group, "vuln_class": vuln_class,
            "date": date, "pair_id": pair_id, "fn": "f", "path": "src/lib.rs"}


def with_sigs(rows):
    for r in rows:
        r.update(assemble.signatures(r["code"]))
    return rows


class SignatureTest(unittest.TestCase):
    def test_norm_hash_ignores_comments_and_whitespace(self):
        self.assertEqual(assemble.signatures(A)["norm_hash"], assemble.signatures(A_COMMENTED)["norm_hash"])
        self.assertNotEqual(assemble.signatures(A)["norm_hash"], assemble.signatures(A_RENAMED)["norm_hash"])

    def test_shape_hash_equal_under_consistent_renaming(self):
        self.assertEqual(assemble.signatures(A)["shape_hash"], assemble.signatures(A_RENAMED)["shape_hash"])
        self.assertNotEqual(assemble.signatures(A)["shape_hash"], assemble.signatures(B)["shape_hash"])

    def test_shape_hash_distinguishes_inconsistent_renaming(self):
        # `x + x` and `x + y` are different code, not a renamed copy
        f1 = "fn f(x: u64, y: u64) -> u64 {\n    let z = x + x;\n    z\n}"
        f2 = "fn f(x: u64, y: u64) -> u64 {\n    let z = x + y;\n    z\n}"
        self.assertNotEqual(assemble.signatures(f1)["shape_hash"], assemble.signatures(f2)["shape_hash"])

    def test_jaccard(self):
        s = assemble.signatures(A)["shingles"]
        self.assertEqual(assemble.jaccard(s, s), 1.0)
        self.assertLess(assemble.jaccard(s, assemble.signatures(B)["shingles"]), 0.5)


class GroupTest(unittest.TestCase):
    def test_canonical_group(self):
        roots = {"ref-finance/burrowland": "neardefi/burrowland"}
        aliases = {"ref-finance/ref-contracts": "rozgo/ref-contracts"}
        self.assertEqual(assemble.canonical_group("ref-finance/burrowland", aliases, roots), "neardefi/burrowland")
        self.assertEqual(assemble.canonical_group("ref-finance/ref-contracts", aliases, roots), "rozgo/ref-contracts")
        self.assertEqual(assemble.canonical_group("o/r", aliases, roots), "o/r")


class CopyGroupTest(unittest.TestCase):
    def fn(self, name, n=12):
        return f"pub fn {name}(&mut self, amount: U128) {{\n" + "".join(
            f"    self.{name}_step_{i}(amount.0, {i});\n" for i in range(n)) + "}"

    def test_repo_copying_several_real_group_functions_joins_that_group(self):
        real = [row("v", self.fn("borrow"), 1, "audit", "o/lend", "logic_error"),
                row("c1", self.fn("repay"), 0, "corpus", "o/lend"), row("c2", self.fn("supply"), 0, "corpus", "o/lend"),
                row("c3", self.fn("withdraw"), 0, "corpus", "o/lend")]
        copy = [row(f"k{i}", self.fn(n).replace("U128", "u128"), 0, "corpus", "x/fork")
                for i, n in enumerate(["borrow", "repay", "supply"])]
        copy.append(row("k_own", self.fn("own_thing"), 0, "corpus", "x/fork"))
        unrelated = [row("u1", self.fn("borrow").replace("U128", "u128"), 0, "corpus", "y/other"),
                     row("u2", self.fn("mint"), 0, "corpus", "y/other")]
        mapping = assemble.copy_groups(with_sigs(real + copy + unrelated))
        self.assertEqual(mapping, {"x/fork": "o/lend"})

    def test_real_groups_of_one_project_merge_into_the_larger(self):
        big = [row(f"b{i}", self.fn(n), 1, "audit", "o/pool", "logic_error") for i, n in enumerate(["a", "b", "c", "d"])]
        small = [row(f"s{i}", self.fn(n).replace("U128", "u128"), 1, "fix_commit", "z/pool-fork", "logic_error")
                 for i, n in enumerate(["a", "b", "c"])]
        copy = [row(f"k{i}", self.fn(n).replace("U128", "u128"), 0, "corpus", "x/fork")
                for i, n in enumerate(["b", "c", "d"])]
        self.assertEqual(assemble.copy_groups(with_sigs(big + small + copy)),
                         {"z/pool-fork": "o/pool", "x/fork": "o/pool"})

    def test_real_groups_sharing_a_few_helpers_stay_apart(self):
        a = [row(f"a{i}", self.fn(f"a_{i}"), 1, "audit", "o/pool", "logic_error") for i in range(40)]
        b = [row(f"b{i}", self.fn(f"b_{i}"), 1, "audit", "z/other", "logic_error") for i in range(37)]
        b += [row(f"h{i}", self.fn(f"a_{i}").replace("U128", "u128"), 0, "fix_commit", "z/other") for i in range(3)]
        self.assertEqual(assemble.copy_groups(with_sigs(a + b)), {})

    def test_code_shared_by_many_repos_does_not_merge(self):
        real = [row("v", self.fn("borrow"), 1, "audit", "o/lend", "logic_error")]
        real += [row(f"s{i}", self.fn(f"std_{i}"), 0, "corpus", "o/lend") for i in range(3)]
        others = [row(f"o{g}{i}", self.fn(f"std_{i}"), 0, "corpus", f"t/tpl{g}") for g in range(6) for i in range(3)]
        self.assertEqual(assemble.copy_groups(with_sigs(real + others)), {})


class ConflictTest(unittest.TestCase):
    def test_corpus_copy_of_real_vulnerable_is_relabelled(self):
        rows = with_sigs([row("r1", A, 1, "audit", "g/real", "missing_access_control"),
                          row("c1", A_COMMENTED, 0, "corpus", "g/other"),
                          row("m1", A, 0, "mutation_original", "g/third", pair_id="m1"),
                          row("c2", B, 0, "corpus", "g/other")])
        out, st = assemble.resolve_conflicts(rows)
        by = {r["id"]: r for r in out}
        self.assertEqual((by["c1"]["label"], by["c1"]["vuln_class"], by["c1"]["source"]),
                         (1, "missing_access_control", "corpus"))
        self.assertTrue(by["c1"]["relabeled_from_real"])
        self.assertEqual(by["m1"]["label"], 1)
        self.assertEqual(by["c2"]["label"], 0)
        self.assertNotIn("relabeled_from_real", by["c2"])
        self.assertEqual(st["relabeled_from_real"], 2)

    def test_real_fixed_identical_to_real_vulnerable_is_dropped(self):
        rows = with_sigs([row("v", A, 1, "fix_commit", vuln_class="logic_error"), row("f", A_COMMENTED, 0, "fix_commit")])
        out, st = assemble.resolve_conflicts(rows)
        self.assertEqual([r["id"] for r in out], ["v"])
        self.assertEqual(st["dropped_real_fixed_same_as_vulnerable"], 1)

    def test_mutant_identical_to_safe_code_is_dropped(self):
        rows = with_sigs([row("f", A, 0, "audit"), row("mut", A, 1, "mutation", vuln_class="signer_auth"),
                          row("c", B, 0, "corpus"), row("mut2", B, 1, "mutation", vuln_class="gas_dos")])
        out, st = assemble.resolve_conflicts(rows)
        self.assertEqual(sorted(r["id"] for r in out), ["c", "f"])
        self.assertEqual(st["dropped_mutant_same_as_label0"], 2)


class SplitTest(unittest.TestCase):
    def real_rows(self, n_groups, post=()):
        rows = []
        for i in range(n_groups):
            g = f"o/g{i:02d}"
            date = "2025-03-01" if g in post else "2023-01-01"
            rows.append(row(f"r{i}", A, 1, "audit", g, ["logic_error", "gas_dos"][i % 2], date))
        return rows

    def test_post_2025_groups_always_in_test_and_seeded(self):
        rows = self.real_rows(40, post={"o/g03", "o/g17"})
        test, info = assemble.pick_test_groups(rows, seed=7)
        self.assertTrue({"o/g03", "o/g17"} <= test)
        self.assertEqual(len(test), 2 + round(0.25 * 38))
        self.assertEqual(test, assemble.pick_test_groups(rows, seed=7)[0])
        self.assertNotEqual(test, assemble.pick_test_groups(rows, seed=8)[0])

    def test_fix_commit_dates_do_not_force_test(self):
        rows = self.real_rows(8)
        rows.append(row("fc", A, 1, "fix_commit", "o/g00", "logic_error", "2026-01-01"))
        _, info = assemble.pick_test_groups(rows, seed=1)
        self.assertEqual(info["time_split_groups"], [])

    def test_random_share_shrinks_when_time_split_is_large(self):
        post = {f"o/g{i:02d}" for i in range(15)}
        rows = self.real_rows(40, post=post)
        test, info = assemble.pick_test_groups(rows, seed=7)
        self.assertTrue(post <= test)
        self.assertEqual(len(test), 16)  # cap 40% of 40 groups
        self.assertEqual(info["random_groups"], 1)

    def test_random_share_shrinks_when_test_holds_too_many_real_rows(self):
        rows = self.real_rows(40, post={"o/g00"})
        rows += [row(f"big{i}", A, 1, "audit", "o/g00", "logic_error", "2023-01-01") for i in range(20)]
        test, info = assemble.pick_test_groups(rows, seed=7)
        n_test = sum(r["group"] in test for r in rows)
        self.assertLessEqual(n_test, 0.40 * len(rows))  # 60 label-1 rows: at most 24 in test
        self.assertEqual(info["random_groups"], 3)

    def test_stratified_by_class(self):
        rows = self.real_rows(40)
        test, _ = assemble.pick_test_groups(rows, seed=3)
        classes = [r["vuln_class"] for r in rows if r["group"] in test]
        self.assertEqual(classes.count("logic_error"), 5)
        self.assertEqual(classes.count("gas_dos"), 5)


class DedupeTest(unittest.TestCase):
    def test_keeps_real_source_first(self):
        rows = with_sigs([row("c", A, 0, "corpus"), row("m", A, 0, "mutation_original"), row("a", A_COMMENTED, 0, "audit"),
                          row("b", B, 0, "corpus")])
        out, n = assemble.dedupe(rows)
        self.assertEqual(sorted(r["id"] for r in out), ["a", "b"])
        self.assertEqual(n, 2)


LONG = "pub fn withdraw(&mut self, amount: U128) {\n" + "".join(
    f"    self.step_{i}(amount.0, {i});\n" for i in range(30)) + "}"


class LeakageTest(unittest.TestCase):
    def test_removes_exact_shape_and_fuzzy_copies(self):
        edited = LONG.replace("self.step_29(amount.0, 29);", "self.step_29(amount.0, 29);\n    log!(\"done\");")
        renamed = LONG.replace("withdraw", "redeem").replace("amount", "value").replace("step_", "stage_")
        test = with_sigs([row("t1", A, 1, "audit", "g/test", "missing_access_control"),
                          row("t2", LONG, 1, "audit", "g/test", "logic_error")])
        train = with_sigs([row("x1", A_COMMENTED, 0, "corpus", "g/train"), row("x2", renamed, 0, "corpus", "g/train"),
                           row("x3", edited, 0, "corpus", "g/train"), row("x4", B, 0, "corpus", "g/train"),
                           row("mut", B.replace("let o", "let p"), 1, "mutation", "g/train", "gas_dos", pair_id="x1")])
        kept, removed = assemble.remove_leaks(train, test)
        self.assertEqual([r["id"] for r in kept], ["x4"])
        self.assertEqual(removed, {"x1": "norm_hash", "x2": "shape_hash", "x3": "jaccard", "mut": "pair_removed"})

    def test_shape_ignores_short_functions_and_non_real_test_rows(self):
        # a guarded setter has the shape of every other guarded setter: not a copy
        renamed = LONG.replace("withdraw", "redeem").replace("amount", "value").replace("step_", "stage_")
        test = with_sigs([row("t1", A, 1, "audit", "g/test", "missing_access_control"),
                          row("t2", LONG, 0, "corpus", "g/test")])
        train = with_sigs([row("x1", A_RENAMED, 0, "corpus", "g/train"), row("x2", renamed, 0, "corpus", "g/train")])
        kept, removed = assemble.remove_leaks(train, test)
        self.assertEqual(removed, {})
        self.assertEqual(len(kept), 2)

    def test_jaccard_against_any_test_row(self):
        edited = LONG.replace("self.step_29(amount.0, 29);", "self.step_29(amount.0, 29);\n    log!(\"done\");")
        test = with_sigs([row("t", LONG, 0, "corpus", "g/test")])
        kept, removed = assemble.remove_leaks(with_sigs([row("x", edited, 0, "corpus", "g/train")]), test)
        self.assertEqual(removed, {"x": "jaccard"})


class SmallTrainTest(unittest.TestCase):
    def test_keeps_labelled_and_caps_corpus_per_group(self):
        rows = [row("p", A, 1, "audit", "g/a", "logic_error"), row("f", A, 0, "audit", "g/a", pair_id="p"),
                row("mo", A, 0, "mutation_original", "g/a", pair_id="mo")]
        rows += [row(f"c{i}", A, 0, "corpus", "g/big") for i in range(50)]
        rows += [row(f"d{i}", A, 0, "corpus", "g/small") for i in range(3)]
        small, cap = assemble.small_train(rows, target=13, seed=1)
        ids = {r["id"] for r in small}
        self.assertTrue({"p", "f", "mo", "d0", "d1", "d2"} <= ids)
        self.assertEqual(len(small), 13)
        self.assertEqual(cap, 7)
        self.assertEqual(small, assemble.small_train(rows, target=13, seed=1)[0])


if __name__ == "__main__":
    unittest.main()
