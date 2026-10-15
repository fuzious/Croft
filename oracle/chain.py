"""Local chain plumbing: anvil process, Foundry artifacts, accounts, deployment of the demo world."""
from __future__ import annotations

import json
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from eth_account import Account
from web3 import Web3

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "contracts" / "out"
ANVIL_MNEMONIC = "test test test test test test test test test test test junk"
E18 = 10**18

Account.enable_unaudited_hdwallet_features()


def anvil_account(index: int):
    return Account.from_mnemonic(ANVIL_MNEMONIC, account_path=f"m/44'/60'/0'/0/{index}")


def artifact(contract: str, file: str | None = None) -> dict:
    data = json.loads((ARTIFACTS / f"{Path(file or contract).name}.sol" / f"{contract}.json").read_text())
    return {"abi": data["abi"], "bytecode": data["bytecode"]["object"]}


class Anvil:
    """A local anvil node for the lifetime of the object."""

    def __init__(self, port: int = 8545, accounts: int = 10):
        self.port = port
        self.proc = subprocess.Popen(
            ["anvil", "--port", str(port), "--accounts", str(accounts), "--silent", "--hardfork", "cancun"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.05)
        else:
            raise RuntimeError("anvil did not start")
        self.url = f"http://127.0.0.1:{port}"

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()


class Chain:
    def __init__(self, url: str):
        self.w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 60}))
        assert self.w3.is_connected(), f"cannot reach {url}"

    def rpc(self, method: str, params: list | None = None):
        resp = self.w3.provider.make_request(method, params or [])
        if "error" in resp:
            raise RuntimeError(f"{method}: {resp['error']}")
        return resp["result"]

    def snapshot(self) -> str:
        return self.rpc("evm_snapshot")

    def revert(self, snap: str):
        assert self.rpc("evm_revert", [snap]), "evm_revert failed"

    def send(self, account, fn_or_tx, value: int = 0):
        """Sign and send a contract function call (or a raw tx dict); return the receipt."""
        if isinstance(fn_or_tx, dict):
            tx = dict(fn_or_tx)
        else:
            tx = fn_or_tx.build_transaction({"from": account.address, "value": value, "gas": 8_000_000})
        tx.setdefault("from", account.address)
        tx["nonce"] = self.w3.eth.get_transaction_count(account.address)
        tx.setdefault("gas", 8_000_000)
        tx.setdefault("chainId", self.w3.eth.chain_id)
        if "maxFeePerGas" not in tx and "gasPrice" not in tx:
            tx["gasPrice"] = self.w3.eth.gas_price
        signed = account.sign_transaction(tx)
        h = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        return self.w3.eth.wait_for_transaction_receipt(h)

    def deploy(self, account, contract: str, *args, file: str | None = None):
        art = artifact(contract, file)
        factory = self.w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
        receipt = self.send(account, factory.constructor(*args))
        assert receipt.status == 1, f"deploy {contract} failed"
        return self.w3.eth.contract(address=receipt.contractAddress, abi=art["abi"])

    def at(self, contract: str, address: str, file: str | None = None):
        return self.w3.eth.contract(address=address, abi=artifact(contract, file)["abi"])


@dataclass
class World:
    """The demo protocol: a gated lending pool priced off a manipulable AMM."""

    chain: Chain
    deployer: object
    relayer: object
    gate: object
    col: object
    usd: object
    amm: object
    lender: object
    pool: object
    labels: dict = field(default_factory=dict)

    @classmethod
    def deploy(cls, chain: Chain, *, price: float = 2000.0, depth_col: float = 1000.0,
               pool_usd: float = 3_000_000.0, lender_usd: float = 20_000_000.0) -> "World":
        deployer, relayer = anvil_account(0), anvil_account(1)
        gate = chain.deploy(deployer, "OracleGate", relayer.address)
        col = chain.deploy(deployer, "MockToken", "Collateral", "COL", file="demo/Protocol")
        usd = chain.deploy(deployer, "MockToken", "US Dollar", "USD", file="demo/Protocol")
        amm = chain.deploy(deployer, "SimpleAMM", col.address, usd.address, file="demo/Protocol")
        lender = chain.deploy(deployer, "FlashLender", file="demo/Protocol")
        pool = chain.deploy(deployer, "LendingPool", gate.address, col.address, usd.address, amm.address,
                            file="demo/Protocol")
        world = cls(chain, deployer, relayer, gate, col, usd, amm, lender, pool)
        world.mint(col, amm.address, depth_col)
        world.mint(usd, amm.address, depth_col * price)
        chain.send(deployer, amm.functions.sync())
        world.mint(usd, lender.address, lender_usd)
        world.mint(usd, pool.address, pool_usd)
        # What the oracle knows about addresses (in production: Etherscan + our protocol registry).
        world.labels = {
            gate.address: {"name": "OracleGate", "kind": "security oracle gate"},
            pool.address: {"name": "LendingPool", "kind": "protected protocol (lending)"},
            amm.address: {"name": "SimpleAMM", "kind": "DEX pool COL/USD (lending pool's price oracle)"},
            lender.address: {"name": "FlashLender", "kind": "flash-loan provider"},
            col.address: {"name": "COL", "kind": "token"},
            usd.address: {"name": "USD", "kind": "stablecoin"},
        }
        return world

    def mint(self, token, to: str, amount: float):
        receipt = self.chain.send(self.deployer, token.functions.mint(to, int(amount * E18)))
        assert receipt.status == 1

    def price(self) -> float:
        return self.amm.functions.spotPrice().call() / E18

    def deploy_user_contract(self, owner, name: str):
        return self.chain.deploy(owner, name, self.pool.address, self.lender.address, file="demo/Strategies")


def sign_request(world: World, signer, to: str, data: bytes | str, value: int = 0, ttl: int = 300) -> tuple[tuple, bytes]:
    """Build and sign a ForwardRequest the way a wallet/dApp would."""
    if isinstance(data, str):
        data = bytes.fromhex(data.removeprefix("0x"))
    now = world.chain.w3.eth.get_block("latest")["timestamp"]
    req = (signer.address, Web3.to_checksum_address(to), value,
           world.gate.functions.nonces(signer.address).call(), now + ttl, data)
    digest = world.gate.functions.digest(req).call()
    sig = Account.unsafe_sign_hash(digest, signer.key)
    return req, sig.signature
