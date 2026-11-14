"""Deploy the contracts a NEAR Intents deposit needs into a sandbox.

Accounts, named like their mainnet roles so that receipt graphs look the same:
- `intents.near`: the verifier (defuse) contract under test, vulnerable v0.4.2 or fixed;
- `omni.bridge.near`: a bridged multi-token (NEP-245) contract that users `mt_batch_transfer_call` into intents.near,
  like HOT Omni's `v2_1.omni.hot.tg` (same name length). It runs `mt_token/` from this directory: a failed
  `mt_on_transfer` refunds the full amounts to the sender, as NEP-245 requires;
- `bridge.near`: mints balances on omni.bridge.near (like a bridge would);
- `usdt.bridge.near`: a NEP-141 token (the near-sdk example `fungible-token.wasm` shipped in the intents repo);
- `wrap.near`: wNEAR (`wnear.wasm` from the intents repo);
- receivers: implicit accounts running the intents repo's `multi-token-receiver-stub`;
- users and attackers: implicit accounts.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from near.intents.synthetic import nearkeys
from near.intents.synthetic.sandbox import NEAR, Account, Chain, failure_of

# build inputs live under the gitignored data dir unless the environment points elsewhere (see README)
BUILD = Path("near/data/intents/synthetic")
V042_DIR = Path(os.environ.get("INTENTS_V042_DIR", BUILD / "intents-v042"))
# defuse.wasm after `wasm-opt -Oz` (see README): the plain cargo build is 1.6 MB and its base64 body exceeds the
# sandbox RPC's request-body limit
WASM_DIR = Path(os.environ.get("INTENTS_SYN_WASM_DIR", BUILD / "wasm"))


# verifier versions: the exploited v0.4.2, and v0.4.2 plus the batch-limit fix that shipped in v0.4.3 (see
# patches/v0.4.2-batch-limit.patch). The later "remove notifications" commit 16d04f6e needs rustc >= 1.95, whose wasm
# uses bulk-memory, which the pinned sandbox (protocol 82) rejects with `PrepareError: Deserialization`.
VERIFIER_WASMS = {"v0.4.2": "defuse-v0.4.2.wasm", "v0.4.3-backport": "defuse-v0.4.2-batchlimit.wasm"}


def wasm_paths(version: str) -> dict[str, Path]:
    """Wasm files for one verifier version."""
    return {
        "verifier": WASM_DIR / VERIFIER_WASMS[version],
        "mt_token": WASM_DIR / "synthetic_mt_token.wasm",
        "stub": WASM_DIR / "multi_token_receiver_stub.wasm",
        "ft": V042_DIR / "releases/fungible-token.wasm",
        "wnear": V042_DIR / "releases/wnear.wasm",
    }


def key_for(label: str) -> nearkeys.KeyPair:
    """Deterministic key per label, so that runs are reproducible."""
    return nearkeys.KeyPair.from_seed(hashlib.sha256(b"intents-synthetic:" + label.encode()).digest())


def _ok(status: dict, what: str) -> dict:
    f = failure_of(status)
    if f is not None:
        raise RuntimeError(f"{what} failed: {json.dumps(f)[:1500]}")
    return status


@dataclass
class World:
    chain: Chain
    root: Account
    version: str
    intents: Account
    omni: Account
    bridge: Account
    usdt: Account
    wrap: Account
    stub_code: bytes
    receivers: list[Account] = field(default_factory=list)

    @property
    def intents_id(self) -> str:
        return self.intents.account_id

    def new_implicit(self, label: str, balance: int = 50 * NEAR) -> Account:
        key = key_for(label)
        account_id = key.implicit_account_id
        _ok(self.root.send(account_id, [nearkeys.transfer(balance)]), f"fund {label}")
        return Account(self.chain, account_id, key)

    def new_receiver(self, label: str) -> Account:
        acc = self.new_implicit(label, 20 * NEAR)
        _ok(acc.send(acc.account_id, [nearkeys.deploy_contract(self.stub_code)]), f"deploy stub {label}")
        self.receivers.append(acc)
        return acc

    def mint_on_omni(self, owner_id: str, token_ids: list[str], amounts: list[int]) -> None:
        """Credit `owner_id` on omni.bridge.near; intents.near names these `nep245:omni.bridge.near:<id>`."""
        _ok(self.bridge.call(self.omni.account_id, "mint", {
            "owner_id": owner_id, "token_ids": token_ids, "amounts": [str(a) for a in amounts]}, gas_tgas=300),
            "mint on omni")

    def give_usdt(self, account_id: str, amount: int) -> None:
        self.register_usdt(account_id)
        _ok(self.root.call(self.usdt.account_id, "ft_transfer", {"receiver_id": account_id, "amount": str(amount)},
                           gas_tgas=30, deposit=1), "ft_transfer")

    def register_usdt(self, account_id: str) -> None:
        _ok(self.root.call(self.usdt.account_id, "storage_deposit", {"account_id": account_id},
                           gas_tgas=30, deposit=12_500_000_000_000_000_000_000), "storage_deposit")


def build_world(chain: Chain, root: Account, version: str) -> World:
    paths = wasm_paths(version)
    code = {k: p.read_bytes() for k, p in paths.items()}

    def deploy(account_id: str, wasm: bytes, init_method: str, init_args: dict, balance: int) -> Account:
        acc = chain.patch_account(account_id, key_for(account_id), balance)
        _ok(acc.send(account_id, [
            nearkeys.deploy_contract(wasm),
            nearkeys.function_call(init_method, json.dumps(init_args).encode(), 300 * 10**12),
        ]), f"deploy {account_id}")
        return acc

    defuse_init = {"config": {"wnear_id": "wrap.near", "fees": {"fee": 0, "fee_collector": "intents.near"},
                              "roles": {}}}
    wrap = deploy("wrap.near", code["wnear"], "new", {}, 100 * NEAR)
    intents = deploy("intents.near", code["verifier"], "new", defuse_init, 5000 * NEAR)
    omni = deploy("omni.bridge.near", code["mt_token"], "new", {}, 100 * NEAR)
    usdt = deploy("usdt.bridge.near", code["ft"], "new_default_meta",
                  {"owner_id": root.account_id, "total_supply": str(10**30)}, 100 * NEAR)
    bridge = chain.patch_account("bridge.near", key_for("bridge.near"), 1000 * NEAR)
    world = World(chain=chain, root=root, version=version, intents=intents, omni=omni, bridge=bridge, usdt=usdt,
                  wrap=wrap, stub_code=code["stub"])
    world.register_usdt(intents.account_id)
    _ok(root.call(wrap.account_id, "storage_deposit", {"account_id": intents.account_id}, gas_tgas=30,
                  deposit=12_500_000_000_000_000_000_000), "wrap.near storage_deposit")
    return world
