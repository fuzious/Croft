"""Fact cards for real mainnet transactions (replayed + traced locally).

A card is the compact, decoded story of a transaction: who called what, which contracts are
fresh/unverified, flash loans, re-entrancy, and who gained or lost how much (USD, and as a share of
what they held). The same pass emits numeric features for the non-LLM baseline.
Rules (docs/JEV_STUDY.md §7): no raw hex, priced numbers, fit Laya's budget, and unverified contracts
stay anonymous so attacker-chosen names never reach the model.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from web3 import Web3

from .sources import CHAINS, Alchemy, Etherscan, NftPrices, Prices

ZERO = "0x0000000000000000000000000000000000000000"
WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
T_TRANSFER = Web3.keccak(text="Transfer(address,address,uint256)").hex().removeprefix("0x")
T_WETH_DEP = Web3.keccak(text="Deposit(address,uint256)").hex().removeprefix("0x")
T_WETH_WD = Web3.keccak(text="Withdrawal(address,uint256)").hex().removeprefix("0x")
T_APPROVAL = Web3.keccak(text="Approval(address,address,uint256)").hex().removeprefix("0x")
T_1155_SINGLE = Web3.keccak(text="TransferSingle(address,address,address,uint256,uint256)").hex().removeprefix("0x")
T_1155_BATCH = Web3.keccak(text="TransferBatch(address,address,address,uint256[],uint256[])").hex().removeprefix("0x")


def _sel(sig: str) -> str:
    return Web3.keccak(text=sig)[:4].hex().removeprefix("0x")


# Flash-loan entry points and the callbacks lenders invoke (either side identifies a flash loan).
FLASH_ENTRY = {_sel(s): s.split("(")[0] for s in [
    "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",   # Aave V2/V3
    "flashLoanSimple(address,address,uint256,bytes,uint16)",                   # Aave V3
    "flashLoan(address,address[],uint256[],bytes)",                            # Balancer
    "flash(address,uint256,uint256,bytes)",                                    # Uniswap V3
    "flashLoan(address,address,uint256,bytes)",                                # ERC-3156 / Maker
    "flashLoan(address,uint256,bytes)",                                        # Morpho
    "operate((address,uint256)[],(uint8,uint256,(bool,uint8,uint8,uint256),uint256,uint256,address,uint256,bytes)[])",  # dYdX
    "flashLoan(uint256,uint256,address,bytes)",                                # DODO DPP/DVM/DSP
]}
FLASH_CALLBACK = {_sel(s): s.split("(")[0] for s in [
    "executeOperation(address[],uint256[],uint256[],address,bytes)",
    "executeOperation(address,uint256,uint256,address,bytes)",
    "receiveFlashLoan(address[],uint256[],uint256[],bytes)",
    "uniswapV3FlashCallback(uint256,uint256,bytes)",
    "onFlashLoan(address,address,uint256,uint256,bytes)",
    "uniswapV2Call(address,uint256,uint256,bytes)",
    "pancakeCall(address,uint256,uint256,bytes)",
    "callFunction(address,(address,uint256),bytes)",
    "onMorphoFlashLoan(uint256,bytes)",
    "DPPFlashLoanCall(address,uint256,uint256,bytes)", "DVMFlashLoanCall(address,uint256,uint256,bytes)",
    "DSPFlashLoanCall(address,uint256,uint256,bytes)", "pancakeV3FlashCallback(uint256,uint256,bytes)",
]}
COMMON = {_sel(s): s.split("(")[0] for s in [
    "transfer(address,uint256)", "transferFrom(address,address,uint256)", "approve(address,uint256)",
    "balanceOf(address)", "deposit()", "withdraw(uint256)", "swap(uint256,uint256,address,bytes)",
    "sync()", "skim(address)", "mint(address)", "burn(address)", "getReserves()",
]}


def usd(x: float) -> str:
    a = abs(x)
    s = f"${a / 1e6:.2f}M" if a >= 1e6 else f"${a / 1e3:.1f}k" if a >= 1e3 else f"${a:.0f}"
    return ("-" if x < 0 else "+") + s


@dataclass
class Party:
    addr: str
    name: str
    kind: str              # signer | eoa | new | unverified | verified | token
    signer_side: bool = False
    note: str = ""


@dataclass
class CardBuilder:
    alchemy: Alchemy
    etherscan: Etherscan
    prices: Prices
    chain: str = "eth"
    _token_meta: dict = field(default_factory=dict)
    nft_prices: NftPrices = field(default_factory=NftPrices)

    def _sym(self, t: str, block: int) -> str:
        if t == "eth":
            return CHAINS[self.chain]["native_symbol"]
        if t.startswith("nft:"):
            return self.token_meta(t[4:], block)[0] + " NFT"
        return self.token_meta(t, block)[0]

    @classmethod
    def for_chain(cls, chain: str) -> "CardBuilder":
        return cls(Alchemy(chain), Etherscan(chain), Prices(chain), chain)

    # ---------- chain metadata ----------
    def _call(self, to: str, data: str, block: int) -> str | None:
        try:
            return self.alchemy.rpc("eth_call", [{"to": to, "data": data}, hex(block)])
        except RuntimeError:
            return None

    def token_meta(self, token: str, block: int) -> tuple[str, int]:
        if token in self._token_meta:
            return self._token_meta[token]
        sym, dec = token[:8], 18
        out = self._call(token, "0x95d89b41", block)  # symbol()
        if out and len(out) > 2:
            raw = bytes.fromhex(out[2:])
            try:
                if len(raw) >= 96:
                    ln = int.from_bytes(raw[32:64], "big")
                    sym = raw[64:64 + ln].decode("utf-8", "ignore") or sym
                else:
                    sym = raw.rstrip(b"\0").decode("utf-8", "ignore") or sym
            except Exception:  # noqa: BLE001
                pass
        out = self._call(token, "0x313ce567", block)  # decimals()
        if out and len(out) > 2:
            try:
                d = int(out, 16)
                dec = d if 0 <= d <= 36 else 18
            except ValueError:
                pass
        sym = "".join(c for c in sym if c.isprintable())[:12]
        self._token_meta[token] = (sym, dec)
        return sym, dec

    def _receipt_price(self, t: str, block: int, ts: int) -> float | None:
        """USD price of a receipt/vault/LP token from its own exchange rate at the PRE-tx state (block - 1)."""
        word = lambda out: int(out[:66], 16) if out and len(out) >= 66 else None  # noqa: E731
        addr = lambda out: ("0x" + out[26:66]) if out and len(out) >= 66 and int(out[:66], 16) else None  # noqa: E731
        dec = self.token_meta(t, block)[1]
        # Yearn v2-style: pricePerShare() x token()
        pps, und = word(self._call(t, "0x99530b06", block - 1)), addr(self._call(t, "0xfc0c546a", block - 1))
        if pps and und and (p := self.prices.usd([und], ts).get(und)):
            return pps / 10 ** self.token_meta(und, block)[1] * p
        # Compound cToken: exchangeRateStored() x underlying()
        rate, und = word(self._call(t, "0x182df0f5", block - 1)), addr(self._call(t, "0x6f307dc3", block - 1))
        if rate and und and (p := self.prices.usd([und], ts).get(und)):
            return rate / 1e18 * 10 ** dec / 10 ** self.token_meta(und, block)[1] * p
        # Aave aToken (non-debt): 1:1 with UNDERLYING_ASSET_ADDRESS()
        und = addr(self._call(t, "0xb16a19de", block - 1))
        if und and "debt" not in self.token_meta(t, block)[0].lower() and (p := self.prices.usd([und], ts).get(und)):
            return p
        # Uniswap V2-style LP: reserves x prices / totalSupply
        t0, t1 = addr(self._call(t, "0x0dfe1681", block - 1)), addr(self._call(t, "0xd21220a7", block - 1))
        res, sup = self._call(t, "0x0902f1ac", block - 1), word(self._call(t, "0x18160ddd", block - 1))
        if t0 and t1 and res and len(res) >= 130 and sup:
            pr = self.prices.usd([t0, t1], ts)
            if t0 in pr and t1 in pr:
                r0, r1 = int(res[2:66], 16), int(res[66:130], 16)
                tvl = r0 / 10 ** self.token_meta(t0, block)[1] * pr[t0] + r1 / 10 ** self.token_meta(t1, block)[1] * pr[t1]
                return tvl / (sup / 10 ** dec)
        return None

    def balance_before(self, holder: str, token: str, block: int) -> float | None:
        if token.startswith("nft:"):
            return None
        if token == "eth":
            try:
                return int(self.alchemy.rpc("eth_getBalance", [holder, hex(block - 1)]), 16) / 1e18
            except RuntimeError:
                return None
        out = self._call(token, "0x70a08231" + holder[2:].rjust(64, "0"), block - 1)
        if not out or len(out) < 3:
            return None
        return int(out[:66], 16) / 10 ** self.token_meta(token, block)[1]

    def creation_block(self, addr: str) -> tuple[str | None, int | None]:
        c = self.etherscan.creation(addr)
        if not c:
            return None, None
        creator = (c.get("contractCreator") or "").lower() or None
        bn = c.get("blockNumber")
        if bn is None and c.get("txHash"):
            tx = self.alchemy.tx(c["txHash"])
            bn = int(tx["blockNumber"], 16) if tx else None
        return creator, int(bn) if bn is not None else None

    # ---------- trace walking ----------
    @staticmethod
    def frames(trace: dict):
        """Successful frames in execution order with depth (reverted subtrees skipped)."""
        def walk(node, depth):
            if node.get("error"):
                return
            yield node, depth
            for c in node.get("calls") or []:
                yield from walk(c, depth + 1)
        yield from walk(trace, 0)

    def build(self, rp: dict, protected: list[str] | str | None = None,
              category: str | None = None) -> tuple[dict, dict, dict]:
        """`protected`: the protocol contracts the guard protects (known in production: whoever enabled us)."""
        tx, trace = rp["tx"], rp["trace"]
        if isinstance(protected, str):
            protected = [protected]
        protected = {p.lower() for p in protected or []}
        block = int(tx["blockNumber"], 16)
        ts = int(rp["block"]["timestamp"], 16)
        signer = tx["from"].lower()
        frames = list(self.frames(trace))

        created = [f["to"].lower() for f, _ in frames if f.get("type") in ("CREATE", "CREATE2") and f.get("to")]
        callers = {f["from"].lower() for f, d in frames if d > 0 and f.get("from")}
        tx_to = (tx.get("to") or "").lower()
        addrs = []
        for f, _ in frames:
            for a in (f.get("to"), f.get("from")):
                if a and a.lower() not in addrs:
                    addrs.append(a.lower())

        # ---- name every party (code + verification + age) ----
        parties: dict[str, Party] = {}
        counters: dict[str, int] = defaultdict(int)
        token_addrs = {lg["address"].lower() for lg in rp["logs"]
                       if lg["topics"] and lg["topics"][0][2:] == T_TRANSFER and len(lg["topics"]) == 3}

        def party(a: str) -> Party:
            a = a.lower()
            if a in parties:
                return parties[a]
            if a == signer:
                p = Party(a, f"signer", "signer", True)
            elif a in created:
                counters["new"] += 1
                p = Party(a, f"contract created in this tx #{counters['new']}", "new", True)
            elif a in token_addrs and self.etherscan.source(a)["verified"]:
                p = Party(a, self.token_meta(a, block)[0] + " token", "token")
            else:
                try:
                    code = self.alchemy.rpc("eth_getCode", [a, hex(block - 1)])
                except RuntimeError:  # e.g. "account not found" on some chains: treat as no code
                    code = "0x"
                # an "EOA" that originates internal calls runs code: EIP-7702 delegation (set before or in this tx)
                delegated = (code or "").startswith("0xef0100") or (
                    code in ("0x", "0x0", None) and a != signer and a in callers)
                if delegated:
                    counters["7702"] += 1
                    p = Party(a, f"7702-delegated EOA #{counters['7702']}", "unverified", a == tx_to,
                              "EOA running delegated code (EIP-7702)" + (", called directly by signer" if a == tx_to else ""))
                elif code in ("0x", "0x0", None):
                    counters["eoa"] += 1
                    p = Party(a, f"other EOA #{counters['eoa']}", "eoa")
                else:
                    src = self.etherscan.source(a)
                    # creation info (age, deployer) matters for unverified code and the tx target only
                    need_age = (not src["verified"]) or a == (tx.get("to") or "").lower()
                    creator, cblock = self.creation_block(a) if need_age else (None, None)
                    by_signer = creator == signer
                    age = (block - cblock) if cblock else None
                    age_s = (f"{age} blocks old" if age is not None and age < 50_000
                             else f"{age // 7200}d old" if age is not None
                             else "age unknown" if need_age else "established")
                    if src["verified"]:
                        base = src["name"] or "verified contract"
                        counters["v:" + base] += 1
                        name = base if counters["v:" + base] == 1 else f"{base} #{counters['v:' + base]}"
                        p = Party(a, name, "verified", by_signer, f"verified, {age_s}"
                                  + (", deployed by signer" if by_signer else ""))
                    else:
                        counters["unv"] += 1
                        # the unverified contract the signer calls directly is the signer's own tool
                        p = Party(a, f"unverified contract #{counters['unv']}", "unverified", by_signer or a == tx_to,
                                  f"unverified, {age_s}" + (", deployed by signer" if by_signer else "")
                                  + (", called directly by signer" if a == tx_to and not by_signer else ""))
            parties[a] = p
            return p

        for a in addrs:
            party(a)

        # ---- function names ----
        abis: dict[str, dict] = {}

        def fn_name(addr: str, data: str) -> str:
            sel = (data or "0x")[2:10]
            if not sel:
                return "receive"
            if sel in FLASH_ENTRY:
                return FLASH_ENTRY[sel]
            if sel in FLASH_CALLBACK:
                return FLASH_CALLBACK[sel]
            p = parties.get(addr.lower())
            if p and p.kind in ("verified", "token"):
                if addr not in abis:
                    src = self.etherscan.source(addr)
                    abi = src["abi"] or []
                    if src["proxy"] and src["implementation"]:
                        abi = abi + (self.etherscan.source(src["implementation"])["abi"] or [])
                    abis[addr] = {}
                    for item in abi:
                        if item.get("type") == "function":
                            try:
                                sig = f"{item['name']}({','.join(_abi_type(i) for i in item['inputs'])})"
                                abis[addr][_sel(sig)] = item["name"]
                            except (KeyError, TypeError):
                                pass
                if sel in abis[addr]:
                    return abis[addr][sel]
            return COMMON.get(sel, "unknown fn")

        # ---- call path, stats, flash loans, re-entrancy ----
        path, flash, reentered, readonly_reentered = [], [], set(), set()
        prot_calls: list[tuple[str, str]] = []  # (caller kind, function) for calls into the protected contract
        stack: list[tuple[int, str]] = []
        max_depth = 0
        n_calls = 0
        for f, depth in frames:
            typ, to = f.get("type"), (f.get("to") or "").lower()
            max_depth = max(max_depth, depth)
            while stack and stack[-1][0] >= depth:
                stack.pop()
            if typ in ("CALL", "DELEGATECALL", "CALLCODE", "STATICCALL") and to:
                n_calls += 1
                if typ != "DELEGATECALL" and any(a == to for _, a in stack[:-1]) and parties[to].kind not in ("token",):
                    (readonly_reentered if typ == "STATICCALL" else reentered).add(parties[to].name)
                stack.append((depth, to))
                if typ in ("STATICCALL", "DELEGATECALL"):  # reads and proxy->implementation hops are noise
                    continue
                name = fn_name(to, f.get("input", "0x"))
                sel = (f.get("input") or "0x")[2:10]
                if to in protected and typ in ("CALL", "CALLCODE"):
                    caller = party(f["from"])
                    prot_calls.append((caller.name if caller.kind in ("signer",) else caller.kind, name))
                if sel in FLASH_ENTRY or (sel == _sel("swap(uint256,uint256,address,bytes)")
                                          and len(f.get("input", "")) > 2 + 8 + 64 * 4 + 64):
                    flash.append(f"{parties[to].name}.{name}")
                if parties[to].kind == "token" and name in ("transfer", "transferFrom", "approve", "balanceOf"):
                    continue
                path.append(f"{parties[to].name}.{name}")
            elif typ in ("CREATE", "CREATE2"):
                path.append(f"create {parties[to].name if to else 'contract'}")
            elif typ == "SELFDESTRUCT":
                path.append("selfdestruct")
        collapsed: list[str] = []
        for s in path:
            if collapsed and collapsed[-1].rsplit(" x", 1)[0] == s:
                head, _, n = collapsed[-1].rpartition(" x")
                collapsed[-1] = f"{s} x{int(n) + 1}" if head == s else f"{s} x2"
            else:
                collapsed.append(s)

        # ---- value flows ----
        flows: dict[tuple[str, str], int] = defaultdict(int)   # (party, token) -> raw amount
        edges: list[tuple[str, str]] = []                       # (from, to) of every value transfer
        for f, _ in frames:
            v = int(f.get("value") or "0x0", 16)
            wrapped = CHAINS[self.chain]["wrapped"]
            if v and f.get("to") and f.get("type") != "DELEGATECALL":
                # the wrapped-native contract's own side of a wrap/unwrap is bookkeeping, not a gain or loss
                if f["from"].lower() != wrapped:
                    flows[(f["from"].lower(), "eth")] -= v
                if f["to"].lower() != wrapped:
                    flows[(f["to"].lower(), "eth")] += v
                edges.append((f["from"].lower(), f["to"].lower()))
        approvals = 0
        minted: dict[str, set] = defaultdict(set)   # token -> recipients of mints in this tx
        burned: dict[str, set] = defaultdict(set)   # holder -> tokens it burned (shares/claims redeemed)
        nft_moves: list[tuple[str, str, str, int]] = []  # (from, to, collection, count) of ERC-721 / ERC-1155 moves
        for lg in rp["logs"]:
            t = lg["topics"]
            if not t:
                continue
            tok, t0 = lg["address"].lower(), t[0][2:]
            amt = int(lg["data"][2:66] or "0", 16) if lg["data"] not in ("0x", "") else 0
            if t0 == T_TRANSFER and len(t) == 4:  # ERC-721: one NFT moved (or minted / burned)
                nft_moves.append(("0x" + t[1][-40:], "0x" + t[2][-40:], tok, 1))
            elif t0 == T_1155_SINGLE and len(t) == 4:
                raw = bytes.fromhex(lg["data"][2:])
                n = int.from_bytes(raw[32:64], "big") if len(raw) >= 64 else 1
                nft_moves.append(("0x" + t[2][-40:], "0x" + t[3][-40:], tok, min(n, 10**6)))
            elif t0 == T_1155_BATCH and len(t) == 4:
                raw = bytes.fromhex(lg["data"][2:])
                try:  # (uint256[] ids, uint256[] values): sum the values array
                    off = int.from_bytes(raw[32:64], "big")
                    cnt = int.from_bytes(raw[off:off + 32], "big")
                    n = sum(int.from_bytes(raw[off + 32 + 32 * i: off + 64 + 32 * i], "big") for i in range(min(cnt, 256)))
                except (ValueError, IndexError):
                    n = 1
                nft_moves.append(("0x" + t[2][-40:], "0x" + t[3][-40:], tok, min(n, 10**6)))
            if t0 == T_TRANSFER and len(t) == 3:
                flows[("0x" + t[1][-40:], tok)] -= amt
                flows[("0x" + t[2][-40:], tok)] += amt
                if amt > 0:
                    edges.append(("0x" + t[1][-40:], "0x" + t[2][-40:]))
                if "0x" + t[1][-40:] == ZERO and tok != CHAINS[self.chain]["wrapped"]:
                    minted[tok].add("0x" + t[2][-40:])
                if "0x" + t[2][-40:] == ZERO and amt > 0:
                    burned["0x" + t[1][-40:]].add(tok)
            elif tok == CHAINS[self.chain]["wrapped"] and t0 == T_WETH_DEP:
                flows[("0x" + t[1][-40:], tok)] += amt
            elif tok == CHAINS[self.chain]["wrapped"] and t0 == T_WETH_WD:
                flows[("0x" + t[1][-40:], tok)] -= amt
            elif t0 == T_APPROVAL and len(t) == 3:
                approvals += 1
        # an EOA that receives value from the signer's contracts is the signer's profit wallet
        has_outflow = {a for (a, _), v in flows.items() if v < 0}
        for frm, to_ in edges:
            if (frm != ZERO and to_ != ZERO and party(frm).signer_side and party(to_).kind == "eoa"
                    and to_ not in has_outflow):
                pt = party(to_)
                if not pt.signer_side:
                    pt.signer_side, pt.note = True, "receives proceeds from the signer's contracts"
        tokens = sorted({tok for (_, tok), v in flows.items() if v})
        debt_underlying = {}
        for t in tokens:
            if t != "eth" and "debt" in self.token_meta(t, block)[0].lower():
                out = self._call(t, "0xb16a19de", block - 1)  # UNDERLYING_ASSET_ADDRESS()
                if out and len(out) >= 66 and int(out[:66], 16):
                    debt_underlying[t] = "0x" + out[26:66]
        px = self.prices.usd(tokens + list(set(debt_underlying.values())), ts)
        # vault shares (ERC-4626): value = convertToAssets(one share) x asset price, read at the PRE-tx state
        for t in tokens:
            if t == "eth" or t in px or t in debt_underlying:
                continue
            asset = self._call(t, "0x38d52e0f", block - 1)  # asset()
            if not asset or len(asset) < 66 or not int(asset[:66], 16):
                continue
            a_addr = "0x" + asset[26:66]
            dec = self.token_meta(t, block)[1]
            conv = self._call(t, "0x07a2d13a" + hex(10 ** dec)[2:].rjust(64, "0"), block - 1)  # convertToAssets
            a_px = self.prices.usd([a_addr], ts).get(a_addr)
            if conv and len(conv) >= 66 and a_px:
                px[t] = int(conv[:66], 16) / 10 ** self.token_meta(a_addr, block)[1] * a_px
        for t in tokens:
            if t == "eth" or t in px or t in debt_underlying:
                continue
            v = self._receipt_price(t, block, ts)
            if v is not None:
                px[t] = v
        for t, u in debt_underlying.items():
            if u in px:
                px[t] = -px[u]  # holding more debt is a loss, repaying it is a gain
            minted.pop(t, None)
        # a token freshly minted to the signer's side has no trustworthy market price in this tx
        minted_to_signer = sorted(t for t, rcpts in minted.items() if any(party(a).signer_side for a in rcpts))
        # supply shock: moving >20% of a token's supply in one tx makes its market price meaningless here
        supply_shock = []
        for t in tokens:
            if t == "eth" or t not in px or t in debt_underlying:
                continue
            moved = sum(v for (a, tt), v in flows.items() if tt == t and v > 0)
            dec = self.token_meta(t, block)[1]
            if moved / 10 ** dec * px[t] < 1e6:
                continue
            out = self._call(t, "0x18160ddd", block - 1)  # totalSupply()
            supply = int(out[:66], 16) if out and len(out) >= 66 else 0
            if supply and moved / supply > 0.2:
                supply_shock.append(t)
                px.pop(t, None)
        legs = []  # (party, token, amount, usd or None)
        for (a, tok), raw in flows.items():
            if not raw or a == ZERO:
                continue
            dec = 18 if tok == "eth" else self.token_meta(tok, block)[1]
            amt = raw / 10 ** dec
            legs.append((a, tok, amt, amt * px[tok] if tok in px else None))

        # NFTs: count per (party, collection); valued at the collection's floor as of this tx (Ethereum only)
        nft_flows: dict[tuple[str, str], int] = defaultdict(int)
        for f_, t_, coll, n in nft_moves:
            if f_ != ZERO:
                nft_flows[(f_, coll)] -= n
            if t_ != ZERO:
                nft_flows[(t_, coll)] += n
        eth_usd = self.prices.usd(["eth"], ts).get("eth") if self.chain == "eth" else None
        nft_floor = {}
        for (a, coll), n in nft_flows.items():
            if not n:
                continue
            if coll not in nft_floor:
                try:
                    fl = self.nft_prices.floor_eth(coll, ts) if eth_usd else None
                except RuntimeError:
                    fl = None
                nft_floor[coll] = fl * eth_usd if fl is not None and eth_usd else None
            legs.append((a, "nft:" + coll, n, n * nft_floor[coll] if nft_floor[coll] is not None else None))

        side = lambda a: party(a).signer_side  # noqa: E731
        signer_usd = sum(u for a, _, _, u in legs if u is not None and side(a))
        gains = sorted([(u, tok, amt) for a, tok, amt, u in legs if side(a) and u and u > 0], reverse=True)
        # net USD per non-signer party across all priced tokens (a swap nets out; a drain does not)
        net = defaultdict(float)
        for a, tok, amt, u in legs:
            if not side(a) and u is not None:
                net[a] += u
        top_losers = sorted(((a, u) for a, u in net.items() if u < -1), key=lambda kv: kv[1])[:3]
        loser_lines, max_drain = [], 0.0
        for a, u in top_losers:
            # biggest outflow token for this party, and what share of its pre-tx holding that was
            out_legs = sorted([(uu, t, x) for b, t, x, uu in legs if b == a and uu is not None and uu < 0])
            uu, tok, amt = out_legs[0]
            pre = self.balance_before(a, tok, block)
            share = (-amt / pre) if pre else None
            if share is not None and party(a).kind != "token":
                max_drain = max(max_drain, min(share, 1.0))
            sym = self._sym(tok, block)
            loser_lines.append(f"{party(a).name} ({party(a).kind}) net loss {usd(u).lstrip('-')}, mostly {sym}"
                               + (f" ({min(share, 1):.0%} of its {sym})" if share else ""))
        eoa_loss = -sum(u for a, u in net.items() if u < 0 and party(a).kind == "eoa")
        unpriced = sorted({(self._sym(t, block))
                           for a, t, amt, u in legs if u is None and side(a) and amt > 0})

        # ---- is the signer an owner of the protected contracts (Ownable owner() / Safe getOwners())? ----
        signer_is_owner = 0
        for pa in protected:
            for sel in ("0x8da5cb5b", "0xa0e67e2b"):
                out = self._call(pa, sel, block - 1)
                if out and signer[2:] in out.lower():
                    signer_is_owner = 1

        # ---- signer history with the protected protocol ----
        prior_to_prot = -1
        if protected:
            hist = self.etherscan.txlist(signer, block - 1, offset=1000) if self.chain == "eth" else []
            if self.chain == "eth":
                prior_to_prot = sum(1 for h in hist if (h.get("to") or "").lower() in protected)

        # ---- the protected protocol ----
        prot = {}
        prot_feats = {"prot_touched": 0, "prot_net_usd": 0.0, "prot_drain_share": 0.0, "prot_n_calls": 0,
                      "prot_called_by_contract": 0, "prot_called_by_fresh": 0, "prot_outflow_signer_ratio": 0.0,
                      "signer_prior_txs_to_prot": prior_to_prot}
        if protected:
            pname = " + ".join(sorted(party(a).name for a in protected))
            p_legs = [(u, t, x, b) for b, t, x, u in legs if b in protected]
            p_net = sum(u for u, _, _, _ in p_legs if u is not None)
            # outflow tokens: the largest priced ones first, then unpriced ones (a drain needs no USD price)
            priced_out = sorted([(u, t, x, b) for u, t, x, b in p_legs if u is not None and u < 0])[:2]
            unpriced_out = [(None, t, x, b) for u, t, x, b in p_legs if u is None and x < 0][:2]
            drain, out_lines = 0.0, []
            for u, t, x, b in priced_out + unpriced_out:
                pre = self.balance_before(b, t, block)
                share = min(-x / pre, 1.0) if pre else None
                drain = max(drain, share or 0.0)
                sym = self._sym(t, block)
                amount = usd(u).lstrip("-") if u is not None else f"{-x:.4g} (unpriced)"
                out_lines.append(f"{amount} {sym} out" + (f" = {share:.0%} of its {sym}" if share else ""))
            fn_counts: dict[str, int] = defaultdict(int)
            for who, fn in prot_calls:
                fn_counts[f"{fn} by {who}"] += 1
            prot = {
                "name": pname, "category": category or "unknown",
                "functions_called": [f"{k}" + (f" x{v}" if v > 1 else "") for k, v in list(fn_counts.items())[:6]]
                or ("not called directly" if not p_legs else "only token transfers"),
                "net_change": usd(p_net) if p_legs else "none",
                "largest_outflows": out_lines or "none",
            }
            out_usd = -sum(u for u, _, _, _ in p_legs if u is not None and u < 0)
            prot["signer_history"] = ("unknown" if prior_to_prot < 0 else
                                      f"{prior_to_prot} earlier txs from this signer to the protocol")
            prot["signer_is_owner"] = bool(signer_is_owner)
            prot_feats = {
                "prot_touched": int(bool(prot_calls or p_legs)), "prot_net_usd": p_net, "prot_drain_share": drain,
                "prot_outflow_signer_ratio": (min(max(signer_usd, 0) / out_usd, 1.0) if out_usd > 0 else 0.0),
                "signer_prior_txs_to_prot": prior_to_prot,
                "prot_n_calls": len(prot_calls),
                "prot_called_by_contract": int(any(w in ("new", "unverified") for w, _ in prot_calls)),
                "prot_called_by_fresh": int(any(w == "new" for w, _ in prot_calls)),
            }

        # ---- claims surrendered by the signer side (redemptions) ----
        side_addrs = {a for a in parties if parties[a].signer_side}
        nft_out = sum(1 for f_, t_, _, _ in nft_moves if f_ in side_addrs and t_ not in side_addrs)
        nft_in = sum(1 for f_, t_, _, _ in nft_moves if t_ in side_addrs and f_ not in side_addrs)
        burns = sorted({t for a in side_addrs for t in burned.get(a, ())})
        prot_paid_signer = any(b in protected for b, _ in edges if b) and any(
            f_ in protected and party(t_).signer_side for f_, t_ in edges)
        redemption_like = int(prot_paid_signer and (nft_out > 0 or bool(burns)))
        # NFTs pulled from other parties to the signer side; from plain wallets (EOAs) is the drainer pattern
        nft_to_signer = sum(n for f_, t_, _, n in nft_moves if t_ in side_addrs and f_ not in side_addrs and f_ != ZERO)
        nft_from_eoa = sum(n for f_, t_, _, n in nft_moves
                           if t_ in side_addrs and f_ != ZERO and f_ not in side_addrs and party(f_).kind == "eoa")
        nft_usd_to_signer = sum(u for a, t, n, u in legs if t.startswith("nft:") and u and n > 0 and side(a))
        nft_from_protocol = sum(n for f_, t_, _, n in nft_moves if t_ in side_addrs and f_ in protected)

        # ---- operation semantics ----
        all_fns = [step.rsplit(".", 1)[-1].split(" x")[0] for step in path]
        prot_fns = [fn for _, fn in prot_calls]

        def has(fns, names=(), prefixes=()):
            return int(any(f in names or f.startswith(prefixes) for f in fns if prefixes or names))

        LIQ = ("liquidationCall", "liquidateBorrow", "liquidate", "absorb", "batchLiquidate", "liquidateTroves")
        ops = {
            "op_liquidation": has(all_fns, LIQ),
            "op_prot_withdraw": has(prot_fns, ("redeem", "redeemUnderlying", "exit", "unstake", "burn"),
                                    ("withdraw", "removeLiquidity", "remove_liquidity", "unstake")),
            "op_prot_deposit": has(prot_fns, ("mint", "supply", "stake", "join"), ("deposit", "addLiquidity", "add_liquidity")),
            "op_prot_borrow": has(prot_fns, ("borrow",)),
            "op_prot_swap": has(prot_fns, ("exchange",), ("swap",)),
            "op_safe_exec": has(prot_fns + all_fns, ("execTransaction", "execTransactionFromModule", "executeTransaction", "execute")),
            "op_prot_admin": has(prot_fns, (), ("set", "upgrade", "transferOwnership", "grantRole", "initialize")),
            "op_prot_flashloan": has(prot_fns, tuple(set(FLASH_ENTRY.values()))),
        }

        # ---- assemble ----
        to = (tx.get("to") or "").lower()
        target = (f"{party(to).name}.{fn_name(to, tx['input'])}" if to else "contract creation")
        nonce = int(tx["nonce"], 16)
        unknown = [p for p in parties.values() if p.kind == "unverified"]
        card = {
            **({"protected_protocol": prot} if prot else {}),
            "signer": f"EOA with nonce {nonce}" + (" (fresh)" if nonce < 5 else ""),
            "target": target + (f" ({party(to).note})" if to and party(to).note else ""),
            "native_sent": f"{int(tx['value'], 16) / 1e18:.4g} {CHAINS[self.chain]['native_symbol']}",
            "contracts": {
                "verified": sum(1 for p in parties.values() if p.kind in ("verified", "token")),
                "unverified": len(unknown),
                "created_in_tx": len(created),
                "deployed_by_signer": sum(1 for p in parties.values() if p.signer_side and p.kind != "signer"),
            },
            "unverified_contracts": [f"{p.name}: {p.note}" for p in unknown[:4]] or "none",
            "call_path": collapsed[:22] + ([f"... +{len(collapsed) - 22} more steps"] if len(collapsed) > 22 else []),
            "calls": {"total": n_calls, "max_depth": max_depth},
            "reentered_contracts": sorted(reentered)[:4] or "none",
            "readonly_reentry": sorted(readonly_reentered)[:3] or "none",
            "flash_loans": flash[:4] or "none",
            "signer_side_net": usd(signer_usd) + (f" (+unpriced {', '.join(unpriced[:4])})" if unpriced else ""),
            "signer_side_gains": [f"{usd(u)} {self._sym(t, block)}"
                                  for u, t, _ in gains[:3]] or "none",
            "largest_losses": loser_lines or "none",
            "third_party_wallet_losses": usd(-eoa_loss).lstrip("-") if eoa_loss >= 1 else "none",
            "tokens_minted_to_signer_side": [self.token_meta(t, block)[0] for t in minted_to_signer[:3]] or "none",
            "supply_shock_tokens": [self.token_meta(t, block)[0] for t in supply_shock[:3]] or "none",
            "nfts_taken_from_other_wallets": nft_from_eoa if nft_from_eoa else "none",
            "claims_surrendered_by_signer": ({"nfts": nft_out, "burned_tokens": [self._sym(t, block) for t in burns[:3]]}
                                             if (nft_out or burns) else "none"),
        }
        feats = {
            "nonce": nonce, "fresh_signer": int(nonce < 5), "eth_sent": int(tx["value"], 16) / 1e18,
            "target_unverified": int(bool(to) and party(to).kind == "unverified"),
            "target_by_signer": int(bool(to) and party(to).signer_side),
            "creation_tx": int(not to), "n_created": len(created), "n_unverified": len(unknown),
            "n_verified": card["contracts"]["verified"], "n_calls": n_calls, "max_depth": max_depth,
            "n_flash": len(flash), "n_reentered": len(reentered), "signer_usd": signer_usd,
            "max_loss_usd": -min([u for _, u in top_losers], default=0.0), "max_drain_share": max_drain,
            "n_unpriced_gains": len(unpriced), "n_approvals": approvals, "n_logs": len(rp["logs"]),
            "eoa_loss_usd": eoa_loss, "n_minted_to_signer": len(minted_to_signer), "n_supply_shock": len(supply_shock),
            "signer_is_owner": signer_is_owner, "n_7702": counters["7702"],
            "n_readonly_reentered": len(readonly_reentered), **ops,
            "n_nft_out_signer": nft_out, "n_nft_in_signer": nft_in, "n_signer_burns": len(burns),
            "redemption_like": redemption_like,
            "n_nft_to_signer": nft_to_signer, "n_nft_from_eoa_to_signer": nft_from_eoa, "nft_usd_to_signer": nft_usd_to_signer,
            "n_nft_from_protocol_to_signer": nft_from_protocol,
            "target_7702": int(bool(tx_to) and party(tx_to).name.startswith("7702")),
            **prot_feats,
        }
        nft_net = defaultdict(int)  # NFTs a verified contract sent to the signer side (gross; mints in between net out)
        for f_, t_, _, n in nft_moves:
            if f_ != ZERO and t_ in side_addrs and not side(f_) and party(f_).kind == "verified":
                nft_net[f_] -= n
        meta = {"losers": [{"addr": a, "kind": party(a).kind, "name": party(a).name, "usd": u} for a, u in top_losers],
                "nft_losers": [{"addr": a, "name": party(a).name, "count": -n}
                               for a, n in sorted(nft_net.items(), key=lambda kv: kv[1])[:2]],
                "signer": signer, "to": to}
        return card, feats, meta


def _abi_type(i: dict) -> str:
    t = i["type"]
    if t.startswith("tuple"):
        return "(" + ",".join(_abi_type(c) for c in i["components"]) + ")" + t[5:]
    return t
