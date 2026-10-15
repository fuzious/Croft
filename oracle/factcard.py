"""Turn a simulation into a compact, human-readable fact card for the decision model.

Rules (docs/JEV_STUDY.md §7): no raw hex, numbers precomputed and priced, unknown contracts stay
anonymous (no names or selectors an attacker controls), and the card fits Laya's ~700-token budget.
"""
from __future__ import annotations

from collections import defaultdict

from web3 import Web3

from .chain import World, artifact
from .simulate import Sim

_LABELED_ABIS = {"OracleGate": ("OracleGate", None), "SimpleAMM": ("SimpleAMM", "demo/Protocol"),
                 "FlashLender": ("FlashLender", "demo/Protocol"), "LendingPool": ("LendingPool", "demo/Protocol")}
_TOKEN_KINDS = {"token", "stablecoin"}


def _selectors() -> dict[str, dict[str, str]]:
    out = {}
    for name, (contract, file) in _LABELED_ABIS.items():
        sel = {}
        for item in artifact(contract, file)["abi"]:
            if item.get("type") == "function":
                sig = f"{item['name']}({','.join(i['type'] if i['type'] != 'tuple' else '(' + ','.join(c['type'] for c in i['components']) + ')' for i in item['inputs'])})"
                sel[Web3.keccak(text=sig)[:4].hex().removeprefix("0x")] = item["name"]
        out[name] = sel
    return out


SELECTORS = _selectors()


def usd(x: float) -> str:
    sign = "-" if x < 0 else "+"
    a = abs(x)
    if a >= 1e6:
        s = f"${a / 1e6:.2f}M"
    elif a >= 1e3:
        s = f"${a / 1e3:.1f}k"
    else:
        s = f"${a:.0f}"
    return s if a < 0.5 else sign + s


def pct(x: float) -> str:
    return f"{x * 100:+.1f}%"


class Namer:
    """Stable, attacker-proof names: registry labels, else 'signer' / 'unlabeled contract #n'."""

    def __init__(self, world: World, signer: str):
        self.labels = world.labels
        self.signer = signer
        self.unknown: dict[str, str] = {}
        self.code = {}
        self.w3 = world.chain.w3

    def __call__(self, addr: str) -> str:
        addr = Web3.to_checksum_address(addr)
        if addr in self.labels:
            return self.labels[addr]["name"]
        if addr == self.signer:
            return "signer"
        if addr not in self.unknown:
            if addr not in self.code:
                self.code[addr] = len(self.w3.eth.get_code(addr)) > 0
            kind = "unlabeled contract" if self.code[addr] else "other EOA"
            self.unknown[addr] = f"{kind} #{sum(1 for v in self.unknown.values() if v.startswith(kind)) + 1}"
        return self.unknown[addr]

    def is_signer_side(self, addr: str) -> bool:
        name = self(addr)
        return name == "signer" or name.startswith("unlabeled contract")


def _call_path(trace: dict, namer: Namer, world: World) -> list[str]:
    steps: list[str] = []

    def walk(node):
        typ = node.get("type", "CALL")
        to = node.get("to")
        if typ in ("CALL", "DELEGATECALL", "CALLCODE") and to:
            to = Web3.to_checksum_address(to)
            label = world.labels.get(to)
            if label is None:
                steps.append(namer(to))
            elif label["kind"] not in _TOKEN_KINDS and label["name"] != "OracleGate":
                fn = SELECTORS.get(label["name"], {}).get(node.get("input", "0x")[2:10], "unknown")
                steps.append(f"{label['name']}.{fn}")
        for child in node.get("calls", []) or []:
            walk(child)

    walk(trace)
    collapsed: list[str] = []
    for s in steps:
        if collapsed and collapsed[-1].split(" x")[0] == s:
            head, _, n = collapsed[-1].partition(" x")
            collapsed[-1] = f"{head} x{int(n or 1) + 1}"
        else:
            collapsed.append(s)
    return collapsed


def build_card(world: World, sim: Sim) -> dict:
    signer = Web3.to_checksum_address(sim.request[0])
    namer = Namer(world, signer)
    p0 = sim.pre_price
    col_addr, usd_addr = world.col.address, world.usd.address
    pool_addr = world.pool.address

    card: dict = {
        "signer": "EOA",
        "target": namer(sim.request[1]) if sim.request[1] not in world.labels
        else f"{world.labels[sim.request[1]]['name']}.{SELECTORS.get(world.labels[sim.request[1]]['name'], {}).get(bytes(sim.request[5])[:4].hex(), 'unknown')}",
    }
    if not sim.ok:
        card["simulation"] = "reverts"
        return card

    card["call_path"] = _call_path(sim.trace, namer, world)

    flash = [e for e in sim.events if e["event"] == "FlashLoan"]
    card["flash_loans"] = [f"{usd(e['amount'] if e['token'] == usd_addr else e['amount'] * p0)} of "
                           f"{namer(e['token'])} to {namer(e['borrower'])}" for e in flash] or "none"

    # price path of COL as the protocol's oracle saw it, and protocol actions at the price of the moment
    price = p0
    prices = [p0]
    actions = []
    for e in sim.events:
        if e["event"] == "Sync":
            price = e["reserve_usd"] / e["reserve_col"]
            prices.append(price)
        elif e["address"] == pool_addr and e["event"] in ("Deposit", "Borrow", "Repay", "Withdraw"):
            value = e["amount"] * (p0 if e["event"] in ("Deposit", "Withdraw") else 1.0)
            asset = "COL" if e["event"] in ("Deposit", "Withdraw") else "USD"
            actions.append(f"{e['event']} {asset} worth {usd(value).lstrip('+')} (fair price) by {namer(e['account'])}, "
                           f"oracle price at that moment {pct(price / p0 - 1)} vs start")
    card["oracle_price_COL"] = {"start": f"${p0:,.0f}", "highest": pct(max(prices) / p0 - 1),
                                "lowest": pct(min(prices) / p0 - 1), "end": pct(prices[-1] / p0 - 1)}
    card["lending_pool_actions"] = actions or "none"

    # net value change per party, at the pre-tx (fair) price
    delta: dict[str, float] = defaultdict(float)
    for e in sim.events:
        if e["event"] != "Transfer" or e["address"] not in (col_addr, usd_addr):
            continue
        v = e["amount"] * (p0 if e["address"] == col_addr else 1.0)
        for addr, sgn in ((e["from"], -1), (e["to"], 1)):
            party = "signer side" if namer.is_signer_side(addr) else namer(addr)
            delta[party] += sgn * v
    card["net_value_change_at_fair_price"] = {k: usd(v) for k, v in sorted(delta.items(), key=lambda kv: kv[1])
                                              if abs(v) >= 1} or "none"
    return card
