"""Checks for honest labels and leak-resistant generated partitions."""
import copy
import gzip
import json
import tempfile
import unittest
from pathlib import Path

from near.intents.synthetic import scenarios as sc
from near.intents.synthetic.families_v2 import (
    BENIGN_MODES, SPLITS, TEMPLATES, OverflowRandom, TemplateRandom, audit_partitions,
    canonicalize_metadata, decorate,
)


class GeneratedFamilyTests(unittest.TestCase):
    def test_semantic_templates_are_disjoint_and_rng_uses_them(self):
        choices = {
            "callback_accounting": ["MaliciousRefund", "ReturnValue", "ReturnValues"],
            "access_control": sc.PRIVATE_METHODS,
            "token_spoofing": ["ft_on_transfer", "mt_on_transfer", "mt_on_transfer_notify_overflow"],
            "resource_exhaustion": ["Panic", "LargeReturn", "ReturnBytes", "ReturnValuesWrongLen"],
        }
        for family, templates in TEMPLATES.items():
            self.assertEqual(len(set(templates)), len(SPLITS))
            for template in templates:
                rng = TemplateRandom(10, family, template)
                self.assertEqual({rng.choice(choices[family]) for _ in range(10)}, {template})
        self.assertEqual(len(set(BENIGN_MODES)), len(SPLITS))
        for order in ("dust_first", "main_first", "interleaved"):
            self.assertEqual(OverflowRandom(1, order).choice(
                ["dust_first", "dust_first", "main_first", "interleaved"]), order)

    def tx(self, h="tx1", split="train", template="template1", group="group1"):
        return {"transaction": {"hash": h}, "_meta": {"outcome": {}, "split": split,
                "template_id": template, "actor_group": group}}

    def test_partitions_reject_duplicate_hashes_templates_and_actors(self):
        first = self.tx()
        valid = self.tx("tx2", "test", "template2", "group2")
        self.assertEqual(audit_partitions([first, valid])["transactions"], 2)
        for invalid in (copy.deepcopy(first), self.tx("tx3", "test", "template1", "group3"),
                        self.tx("tx4", "test", "template4", "group1")):
            with self.assertRaises(ValueError):
                audit_partitions([first, invalid])
        first["transaction"]["signer_id"] = "same.near"
        valid["transaction"]["signer_id"] = "same.near"
        with self.assertRaisesRegex(ValueError, "signer account"):
            audit_partitions([first, valid])

    def test_metadata_migration_preserves_executed_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            original = self.tx()
            original["_meta"].update(label=1, family="callback_accounting", attack_family="notify_refund_overask")
            for split in SPLITS:
                with gzip.open(folder / f"{split}.jsonl.gz", "wt") as f:
                    f.write(json.dumps(original) + "\n")
            report = canonicalize_metadata(folder, "test-chain")
            with gzip.open(folder / "train.jsonl.gz", "rt") as f:
                migrated = json.loads(f.readline())
            self.assertEqual(migrated["transaction"], original["transaction"])
            self.assertEqual(migrated["_meta"]["attack_family"], "callback_accounting")
            self.assertEqual(migrated["_meta"]["scenario_family"], "notify_refund_overask")
            self.assertEqual(migrated["_meta"]["sandbox_run_id"], "test-chain")
            self.assertEqual(set(report), set(SPLITS))

    def test_exploit_role_requires_measured_ghost_credit(self):
        kwargs = dict(family="callback_accounting", split="train", template="overask",
                      actor_group="a", pair="1", benign=False)
        raw = self.tx()
        raw["_meta"]["attack_family"] = "notify_refund_overask"
        tx = decorate(raw, **kwargs)
        self.assertEqual(tx["_meta"]["role"], "attempt")
        self.assertEqual(tx["_meta"]["source"], "sandbox")
        self.assertEqual(tx["_meta"]["label"], 1)
        self.assertEqual(tx["_meta"]["attack_family"], "callback_accounting")
        self.assertEqual(tx["_meta"]["scenario_family"], "notify_refund_overask")
        tx["_meta"]["outcome"]["ghost_credit"] = "1"
        self.assertEqual(decorate(tx, **kwargs)["_meta"]["role"], "exploit")
        kwargs["benign"] = True
        with self.assertRaisesRegex(ValueError, "ghost credit"):
            decorate(tx, **kwargs)
        tx["_meta"]["outcome"] = {"failures": ["GasExceeded"]}
        tx = decorate(tx, **kwargs)
        self.assertEqual(tx["_meta"]["label"], 0)
        self.assertEqual(tx["_meta"]["role"], "benign")


if __name__ == "__main__":
    unittest.main()
