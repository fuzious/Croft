"""Re-execute a historical mainnet transaction on a local anvil fork and trace it.

This is the same operation the live oracle performs on a not-yet-mined transaction: fork the state
the tx would run against, execute it as its sender, trace it. Alchemy free tier serves archive state
but not debug traces, so tracing happens locally in anvil.
"""
from __future__ import annotations

import socket
from pathlib import Path
import subprocess
import time
from dataclasses import dataclass, field

import requests

from .sources import Alchemy


@dataclass
class Replay:
    tx_hash: str
    tx: dict
    block: dict
    ok: bool                      # replay executed (status 1)
    matched: bool                 # same status and log count as on mainnet
    orig_status: int
    trace: dict | None = None     # callTracer with logs
    logs: list = field(default_factory=list)
    error: str | None = None

    @property
    def block_number(self) -> int:
        return int(self.tx["blockNumber"], 16)

    @property
    def timestamp(self) -> int:
        return int(self.block["timestamp"], 16)


class Replayer:
    def __init__(self, port: int = 8645, alchemy: Alchemy | None = None, cups: int = 300,
                 upstream: str | None = None):
        self.alchemy = alchemy or Alchemy()
        self.upstream = upstream or self.alchemy.url  # archive node anvil forks from
        self.port = port
        self.cups = cups
        self.url = f"http://127.0.0.1:{port}"
        self.log = open(Path(__file__).resolve().parents[1] / "runs" / f"anvil_{port}.log", "ab")
        self._start()

    def _start(self):
        self.proc = subprocess.Popen(
            ["anvil", "--fork-url", self.upstream, "--port", str(self.port),
             "--retries", "10", "--timeout", "120000", "--compute-units-per-second", str(self.cups)],
            stdout=subprocess.DEVNULL, stderr=self.log,
        )
        deadline = time.time() + 60
        while time.time() < deadline:
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", self.port)) == 0:
                    return
            time.sleep(0.2)
        raise RuntimeError("anvil fork did not start")

    def restart(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=10)
        self._start()

    def close(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def rpc(self, method: str, params: list):
        r = requests.post(self.url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                          timeout=600).json()
        if "error" in r:
            raise RuntimeError(f"{method}: {r['error'].get('message', r['error'])}")
        return r["result"]

    def replay(self, tx_hash: str) -> Replay:
        """Replay at the start of its block; if that diverges from mainnet, replay again after the earlier
        same-block txs that share its sender or touch the contracts it touched (attacker setup txs, etc.).
        One automatic anvil restart if the node died or dropped the connection."""
        for attempt in range(2):
            try:
                r = self._replay(tx_hash)
                if r.error is None and not r.matched:
                    r2 = self._replay(tx_hash, prefix_touching=_touched(r.trace) | {r.tx["from"].lower()})
                    if r2.matched or (r2.ok and not r.ok):
                        return r2
                return r
            except requests.ConnectionError:
                if attempt:
                    raise
                self.restart()

    def _send(self, tx: dict, timestamp: int) -> tuple[str, dict]:
        self.rpc("anvil_impersonateAccount", [tx["from"]])
        self.rpc("anvil_setNextBlockBaseFeePerGas", ["0x0"])
        self.rpc("evm_setNextBlockTimestamp", [timestamp])
        send = {"from": tx["from"], "data": tx["input"], "value": tx["value"], "gas": tx["gas"], "gasPrice": "0x0"}
        if tx.get("to"):
            send["to"] = tx["to"]
        h = self.rpc("eth_sendTransaction", [send])
        receipt = self.rpc("eth_getTransactionReceipt", [h])
        if receipt is None:  # zero-gas-price txs sit in the pool despite automine
            self.rpc("evm_mine", [])
            receipt = self.rpc("eth_getTransactionReceipt", [h])
        if receipt is None:
            raise RuntimeError("replayed tx was not mined")
        return h, receipt

    def _replay(self, tx_hash: str, prefix_touching: set[str] | None = None) -> Replay:
        tx = self.alchemy.tx(tx_hash)
        if tx is None:
            raise LookupError(f"{tx_hash} not found on mainnet")
        receipt = self.alchemy.receipt(tx_hash)
        n = int(tx["blockNumber"], 16)
        block = self.alchemy.block(n)
        orig_status = int(receipt["status"], 16)
        ts = int(block["timestamp"], 16)

        self.rpc("anvil_reset", [{"forking": {"jsonRpcUrl": self.upstream, "blockNumber": n - 1}}])
        self.rpc("anvil_setCoinbase", [block["miner"]])
        parent_ts = int(self.rpc("eth_getBlockByNumber", [hex(n - 1), False])["timestamp"], 16)
        prefix = []
        if prefix_touching:
            full = self.alchemy.rpc("eth_getBlockByNumber", [hex(n), True])
            idx = int(tx["transactionIndex"], 16)
            prefix = [p for p in full["transactions"][:idx]
                      if p["from"].lower() in prefix_touching or (p.get("to") or "").lower() in prefix_touching][:30]
        try:
            for i, p in enumerate(prefix):
                self._send(p, parent_ts + 1 + i)
            local_hash, local = self._send(tx, max(ts, parent_ts + 1 + len(prefix)))
        except RuntimeError as e:
            return Replay(tx_hash, tx, block, ok=False, matched=False, orig_status=orig_status, error=str(e))
        status = int(local["status"], 16)
        trace = self.rpc("debug_traceTransaction", [local_hash, {"tracer": "callTracer",
                                                                 "tracerConfig": {"withLog": True}}])
        matched = status == orig_status and len(local["logs"]) == len(receipt["logs"])
        return Replay(tx_hash, tx, block, ok=status == 1, matched=matched, orig_status=orig_status,
                      trace=trace, logs=local["logs"])


def _touched(trace: dict | None) -> set[str]:
    out: set[str] = set()

    def walk(node):
        if node.get("to"):
            out.add(node["to"].lower())
        for c in node.get("calls") or []:
            walk(c)

    if trace:
        walk(trace)
    return out
