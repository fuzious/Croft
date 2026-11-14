"""Run a local NEAR sandbox node and send signed transactions to it over JSON-RPC.

The node binary is the one the intents repo pins through its `near-sandbox = "0.3.4"` dependency, whose
`DEFAULT_NEAR_SANDBOX_VERSION` is 2.10.2. `install_binary` fetches the same tarball that crate fetches.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import tarfile
import threading
import time
from pathlib import Path

import httpx

from near.intents.synthetic import nearkeys

SANDBOX_VERSION = "2.10.2"
SANDBOX_URL = ("https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/Darwin-arm64/"
               f"{SANDBOX_VERSION}/near-sandbox.tar.gz")
TGAS = 10**12
NEAR = 10**24


def default_binary() -> Path:
    env = os.environ.get("NEAR_SANDBOX_BIN_PATH")
    if env:
        return Path(env)
    return Path.home() / ".near" / f"near-sandbox-{SANDBOX_VERSION}" / "near-sandbox"


def install_binary(dest: Path) -> Path:
    """Download the pinned sandbox binary to `dest` unless it is already there."""
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tarball = dest.parent / "near-sandbox.tar.gz"
    with httpx.stream("GET", SANDBOX_URL, follow_redirects=True, timeout=600) as resp:
        resp.raise_for_status()
        with open(tarball, "wb") as fh:
            for chunk in resp.iter_bytes():
                fh.write(chunk)
    with tarfile.open(tarball) as tf:
        member = next(m for m in tf.getmembers() if m.name.endswith("/near-sandbox") and m.isfile())
        with tf.extractfile(member) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
    dest.chmod(0o755)
    tarball.unlink()
    return dest


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Node:
    """A sandbox node process with its own home directory."""

    def __init__(self, binary: Path, home: Path, block_delay_ms: int = 100):
        self.binary = binary
        self.home = home
        self.block_delay_ms = block_delay_ms
        self.proc: subprocess.Popen | None = None
        self._log = None
        self.rpc_url = ""

    def start(self) -> "Node":
        if not (self.home / "genesis.json").exists():
            self.home.mkdir(parents=True, exist_ok=True)
            subprocess.run([str(self.binary), "--home", str(self.home), "init", "--fast"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cfg_path = self.home / "config.json"
            cfg = json.loads(cfg_path.read_text())
            cfg.setdefault("rpc", {}).setdefault("limits_config", {})["json_payload_max_size"] = 1024**3
            cfg.setdefault("store", {})["max_open_files"] = 3000
            delay = {"secs": 0, "nanos": self.block_delay_ms * 1_000_000}
            cfg.setdefault("consensus", {})["min_block_production_delay"] = delay
            cfg["consensus"]["max_block_production_delay"] = {"secs": 0, "nanos": 3 * self.block_delay_ms * 1_000_000}
            cfg_path.write_text(json.dumps(cfg))
        rpc_port, net_port = _free_port(), _free_port()
        self.rpc_url = f"http://127.0.0.1:{rpc_port}"
        self._log = open(self.home / "node.log", "ab")
        self.proc = subprocess.Popen(
            [str(self.binary), "--home", str(self.home), "run", "--rpc-addr", f"127.0.0.1:{rpc_port}",
             "--network-addr", f"127.0.0.1:{net_port}"], stdout=self._log, stderr=self._log)
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                if httpx.get(f"{self.rpc_url}/status", timeout=2).status_code == 200:
                    return self
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        self.stop()
        raise RuntimeError(f"sandbox did not start; see {self.home / 'node.log'}")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self._log is not None:
            self._log.close()
            self._log = None

    def root_key(self) -> tuple[str, nearkeys.KeyPair]:
        """The genesis validator account (`test.near`) and its key, as written by `init`."""
        vk = json.loads((self.home / "validator_key.json").read_text())
        return vk["account_id"], nearkeys.KeyPair.from_secret_key(vk.get("secret_key") or vk["private_key"])


class RpcError(RuntimeError):
    pass


class Rpc:
    def __init__(self, url: str):
        self.url = url
        self._local = threading.local()

    def _client(self) -> httpx.Client:
        c = getattr(self._local, "client", None)
        if c is None:
            c = self._local.client = httpx.Client(timeout=120)
        return c

    def call(self, method: str, params) -> dict:
        body = {"jsonrpc": "2.0", "id": "x", "method": method, "params": params}
        for attempt in range(5):
            try:
                resp = self._client().post(self.url, json=body)
                break
            except httpx.HTTPError:
                if attempt == 4:
                    raise
                time.sleep(1)
        if resp.status_code != 200 and not resp.content.startswith(b"{"):
            raise RpcError(f"HTTP {resp.status_code}: {resp.text[:500]}")
        out = resp.json()
        if "error" in out:
            raise RpcError(json.dumps(out["error"])[:2000])
        return out["result"]


class Account:
    """A signing account. Nonces are tracked locally; sends from one account are serialized by a lock."""

    def __init__(self, chain: "Chain", account_id: str, key: nearkeys.KeyPair):
        self.chain = chain
        self.account_id = account_id
        self.key = key
        self._nonce: int | None = None
        self._lock = threading.Lock()

    def _next_nonce(self) -> int:
        for _ in range(60):
            if self._nonce is not None:
                break
            # a key just added (or patched into state) is visible only once its block is final
            ak = self.chain.rpc.call("query", {"request_type": "view_access_key", "finality": "final",
                                                "account_id": self.account_id,
                                                "public_key": self.key.public_key_str})
            if "nonce" in ak:
                self._nonce = ak["nonce"]
            else:
                time.sleep(0.3)
        if self._nonce is None:
            raise RpcError(f"no access key for {self.account_id}")
        self._nonce += 1
        return self._nonce

    def send(self, receiver_id: str, actions: list[bytes], wait_until: str = "FINAL") -> dict:
        """Sign, send and wait. Returns the EXPERIMENTAL_tx_status result (transaction, receipts, outcomes)."""
        with self._lock:
            return self._send(receiver_id, actions, wait_until)

    def _send(self, receiver_id: str, actions: list[bytes], wait_until: str) -> dict:
        block = self.chain.rpc.call("block", {"finality": "final"})
        tx = nearkeys.serialize_transaction(self.account_id, self.key.public_key, self._next_nonce(), receiver_id,
                                            nearkeys.b58decode(block["header"]["hash"]), actions)
        signed, tx_hash = nearkeys.sign_transaction(self.key, tx)
        try:
            self.chain.rpc.call("send_tx", {"signed_tx_base64": base64.b64encode(signed).decode(),
                                            "wait_until": wait_until})
        except RpcError as e:
            # a tx whose execution fails is still returned as a result; an RPC error here means it was not accepted
            if "InvalidNonce" in str(e):
                self._nonce = None
            if "TIMEOUT" not in str(e).upper():
                raise
        return self.chain.tx_status(nearkeys.b58encode(tx_hash), self.account_id)

    def call(self, contract_id: str, method: str, args: dict | bytes | None = None, gas_tgas: int = 300,
             deposit: int = 0) -> dict:
        raw = args if isinstance(args, bytes) else json.dumps(args or {}).encode()
        return self.send(contract_id, [nearkeys.function_call(method, raw, gas_tgas * TGAS, deposit)])

    def create_subaccount(self, name: str, balance: int, key: nearkeys.KeyPair | None = None,
                          code: bytes | None = None) -> "Account":
        key = key or self.key
        account_id = f"{name}.{self.account_id}"
        actions = [nearkeys.create_account(), nearkeys.transfer(balance), nearkeys.add_full_access_key(key.public_key)]
        if code is not None:
            actions.append(nearkeys.deploy_contract(code))
        st = self.send(account_id, actions)
        _require_success(st, f"create {account_id}")
        return Account(self.chain, account_id, key)


def _require_success(status: dict, what: str) -> None:
    if failure_of(status) is not None:
        raise RuntimeError(f"{what} failed: {json.dumps(failure_of(status))[:1500]}")


def failure_of(status: dict):
    """First receipt failure in a tx status, or the tx-level failure, else None."""
    st = status.get("status", {})
    if isinstance(st, dict) and "Failure" in st:
        return st["Failure"]
    for ro in status.get("receipts_outcome", []):
        s = ro["outcome"]["status"]
        if isinstance(s, dict) and "Failure" in s:
            return s["Failure"]
    return None


class Chain:
    def __init__(self, rpc: Rpc):
        self.rpc = rpc
        self._blocks: dict[str, dict] = {}
        self._lock = threading.Lock()

    def tx_status(self, tx_hash: str, sender_id: str) -> dict:
        for attempt in range(60):
            try:
                return self.rpc.call("EXPERIMENTAL_tx_status", {"tx_hash": tx_hash, "sender_account_id": sender_id,
                                                                "wait_until": "FINAL"})
            except RpcError as e:
                if attempt == 59 or ("UNKNOWN_TRANSACTION" not in str(e) and "TIMEOUT" not in str(e).upper()):
                    raise
                time.sleep(0.5)
        raise AssertionError("unreachable")

    def block(self, block_hash: str) -> dict:
        with self._lock:
            hit = self._blocks.get(block_hash)
        if hit is None:
            hit = self.rpc.call("block", {"block_id": block_hash})["header"]
            with self._lock:
                self._blocks[block_hash] = hit
        return hit

    def view(self, contract_id: str, method: str, args: dict | None = None):
        res = self.rpc.call("query", {"request_type": "call_function", "finality": "final", "account_id": contract_id,
                                      "method_name": method,
                                      "args_base64": base64.b64encode(json.dumps(args or {}).encode()).decode()})
        return json.loads(bytes(res["result"]).decode() or "null")

    def patch_account(self, account_id: str, key: nearkeys.KeyPair, amount: int) -> Account:
        """Create an arbitrary (e.g. top-level) account directly in state with `sandbox_patch_state`.

        The node sometimes drops a patch (seen about 1 in 20 runs); re-send it until the access key is visible.
        """
        for _ in range(5):
            self._send_patch(account_id, key, amount)
            for _ in range(20):
                ak = self.rpc.call("query", {"request_type": "view_access_key", "finality": "final",
                                             "account_id": account_id, "public_key": key.public_key_str})
                if "nonce" in ak:
                    return Account(self, account_id, key)
                time.sleep(0.25)
        raise RpcError(f"sandbox_patch_state did not create {account_id}")

    def _send_patch(self, account_id: str, key: nearkeys.KeyPair, amount: int) -> None:
        self.rpc.call("sandbox_patch_state", {"records": [
            {"Account": {"account_id": account_id, "account": {
                "amount": str(amount), "locked": "0", "code_hash": "11111111111111111111111111111111",
                "storage_usage": 182}}},
            {"AccessKey": {"account_id": account_id, "public_key": key.public_key_str,
                           "access_key": {"nonce": 0, "permission": "FullAccess"}}},
        ]})
