"""Simulate an exact ForwardRequest as the relayer would submit it, then roll the chain back.

Local POC: snapshot -> mine the real execute() tx -> trace + read post-state -> revert.
Production: the same against a fork of mainnet head (anvil --fork-url / revm).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from web3 import Web3
from web3.exceptions import ContractLogicError

from .chain import E18, World

TOPICS = {
    Web3.keccak(text=sig).hex().removeprefix("0x"): name
    for name, sig in {
        "Transfer": "Transfer(address,address,uint256)",
        "Sync": "Sync(uint256,uint256)",
        "Swap": "Swap(address,address,uint256,uint256,address)",
        "FlashLoan": "FlashLoan(address,address,uint256)",
        "Deposit": "Deposit(address,uint256)",
        "Borrow": "Borrow(address,uint256)",
        "Repay": "Repay(address,uint256)",
        "Withdraw": "Withdraw(address,uint256)",
    }.items()
}


def _addr(topic) -> str:
    return Web3.to_checksum_address("0x" + bytes(topic)[-20:].hex())


def _words(data) -> list[int]:
    raw = bytes(data)
    return [int.from_bytes(raw[i:i + 32], "big") for i in range(0, len(raw), 32)]


@dataclass
class Sim:
    request: tuple
    ok: bool
    revert_reason: str | None = None
    pre_price: float = 0.0
    events: list[dict] = field(default_factory=list)   # decoded logs, in execution order
    trace: dict | None = None                         # callTracer output
    positions_after: dict = field(default_factory=dict)  # pool account -> (collateral COL, debt USD)
    positions_before: dict = field(default_factory=dict)


def decode_logs(logs) -> list[dict]:
    events = []
    for log in logs:
        topics = log["topics"]
        name = TOPICS.get(bytes(topics[0]).hex()) if topics else None
        if name is None:
            continue
        w = _words(log["data"])
        ev = {"event": name, "address": Web3.to_checksum_address(log["address"])}
        if name == "Transfer":
            ev.update({"from": _addr(topics[1]), "to": _addr(topics[2]), "amount": w[0] / E18})
        elif name == "Sync":
            ev.update({"reserve_col": w[0] / E18, "reserve_usd": w[1] / E18})
        elif name == "Swap":
            ev.update({"sender": _addr(topics[1]), "token_in": _addr(topics[2]),
                       "amount_in": w[0] / E18, "amount_out": w[1] / E18})
        elif name == "FlashLoan":
            ev.update({"borrower": _addr(topics[1]), "token": _addr(topics[2]), "amount": w[0] / E18})
        else:
            ev.update({"account": _addr(topics[1]), "amount": w[0] / E18})
        events.append(ev)
    return events


def _positions(world: World, accounts) -> dict:
    out = {}
    for a in accounts:
        out[a] = (world.pool.functions.collateralOf(a).call() / E18, world.pool.functions.debtOf(a).call() / E18)
    return out


def simulate(world: World, request: tuple, signature: bytes) -> Sim:
    chain = world.chain
    fn = world.gate.functions.execute(request, signature)
    pre_price = world.price()
    try:
        fn.call({"from": world.relayer.address, "value": request[2]})
    except ContractLogicError as e:
        return Sim(request, ok=False, revert_reason=str(e), pre_price=pre_price)

    snap = chain.snapshot()
    try:
        receipt = chain.send(world.relayer, fn, value=request[2])
        if receipt.status != 1:
            return Sim(request, ok=False, revert_reason="reverted on execution", pre_price=pre_price)
        tx_hash = "0x" + bytes(receipt.transactionHash).hex()
        trace = chain.rpc("debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}])
        events = decode_logs(receipt.logs)
        accounts = sorted({e["account"] for e in events if "account" in e})
        after = _positions(world, accounts)
    finally:
        chain.revert(snap)
    before = _positions(world, accounts)
    return Sim(request, ok=True, pre_price=pre_price, events=events, trace=trace,
               positions_after=after, positions_before=before)


def bad_debt_created(world: World, sim: Sim) -> float:
    """Ground truth used only for labelling: USD of debt this tx added beyond what the collateral
    supports at the PRE-tx (fair) price. Not shown to the model."""
    ltv = world.pool.functions.LTV_BPS().call() / 10_000
    total = 0.0
    for acct, (col_after, debt_after) in sim.positions_after.items():
        _, debt_before = sim.positions_before.get(acct, (0.0, 0.0))
        if debt_after <= debt_before:
            continue
        excess = debt_after - col_after * sim.pre_price * ltv
        total += max(0.0, min(excess, debt_after - debt_before))
    return total
