"""External data with an on-disk cache: Alchemy (archive RPC), Etherscan (code metadata), DefiLlama (prices)."""
from __future__ import annotations

import hashlib
import random
import json
import os
import threading
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "data" / "cache"
load_dotenv(ROOT / ".env")


def _cached(namespace: str, key: str, fetch):
    path = CACHE / namespace / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")
    if path.exists():
        return json.loads(path.read_text())
    value = fetch()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return value


class RateLimiter:
    def __init__(self, per_second: float):
        self.interval = 1.0 / per_second
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self):
        with self.lock:
            delay = self.last + self.interval - time.time()
            if delay > 0:
                time.sleep(delay)
            self.last = time.time()


CHAINS = {
    "eth": {"alchemy": "eth-mainnet", "chainid": 1, "llama": "ethereum", "native": "coingecko:ethereum",
            "native_symbol": "ETH", "wrapped": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"},
    "bsc": {"alchemy": "bnb-mainnet", "chainid": 56, "llama": "bsc", "native": "coingecko:binancecoin",
            "native_symbol": "BNB", "wrapped": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"},
    "base": {"alchemy": "base-mainnet", "chainid": 8453, "llama": "base", "native": "coingecko:ethereum",
             "native_symbol": "ETH", "wrapped": "0x4200000000000000000000000000000000000006"},
    "polygon": {"alchemy": "polygon-mainnet", "chainid": 137, "llama": "polygon", "native": "coingecko:matic-network",
                "native_symbol": "POL", "wrapped": "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"},
    "arbitrum": {"alchemy": "arb-mainnet", "chainid": 42161, "llama": "arbitrum", "native": "coingecko:ethereum",
                 "native_symbol": "ETH", "wrapped": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1"},
    "optimism": {"alchemy": "opt-mainnet", "chainid": 10, "llama": "optimism", "native": "coingecko:ethereum",
                 "native_symbol": "ETH", "wrapped": "0x4200000000000000000000000000000000000006"},
}


def alchemy_key(which: int = 0) -> str:
    """Key 0: ALCHEMY_KEY in .env. Key 1: "alchemy_key" in rpc.json (separate rate-limit budget)."""
    if which == 0:
        return os.environ["ALCHEMY_KEY"]
    return json.loads((ROOT / "rpc.json").read_text())["alchemy_key"]


class Alchemy:
    def __init__(self, chain: str = "eth", key: int = 0):
        self.chain = chain
        self.url = f"https://{CHAINS[chain]['alchemy']}.g.alchemy.com/v2/{alchemy_key(key)}"
        self.namespace = "alchemy" if chain == "eth" else f"alchemy_{chain}"
        self.limit = RateLimiter(20)

    def rpc(self, method: str, params: list, cache: bool = True):
        def fetch():
            for attempt in range(10):
                self.limit.wait()
                try:
                    r = requests.post(self.url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                                      timeout=60)
                except requests.RequestException:
                    time.sleep(2 ** attempt)
                    continue
                if r.status_code == 429:
                    time.sleep(min(2 ** attempt, 30) * (0.5 + random.random()))
                    continue
                body = r.json()
                if "error" in body:
                    raise RuntimeError(f"{method}: {body['error']}")
                return body["result"]
            raise RuntimeError(f"{method}: rate limited")

        return _cached(self.namespace, json.dumps([method, params]), fetch) if cache else fetch()

    def tx(self, h: str) -> dict | None:
        return self.rpc("eth_getTransactionByHash", [h])

    def receipt(self, h: str) -> dict | None:
        return self.rpc("eth_getTransactionReceipt", [h])

    def block(self, n: int) -> dict:
        return self.rpc("eth_getBlockByNumber", [hex(n), False])


class Drpc(Alchemy):
    """Keyed dRPC endpoints from rpc.json (gitignored). On Ethereum it serves debug_traceTransaction, so
    historical txs can be traced exactly as they ran on mainnet instead of being replayed."""

    KEYS = {"eth": "mainnet", "bsc": "bnb", "polygon": "polygon", "base": "base"}

    def __init__(self, chain: str = "eth"):
        self.chain = chain
        self.url = json.loads((ROOT / "rpc.json").read_text())[self.KEYS[chain]]
        self.namespace = f"drpc_{chain}"
        self.limit = RateLimiter(8)


class Etherscan:
    API = "https://api.etherscan.io/v2/api"

    def __init__(self, chain: str = "eth"):
        self.key = os.environ["ETHERSCAN_API_KEY"]
        self.chainid = CHAINS[chain]["chainid"]
        self.limit = RateLimiter(4)

    def call(self, **params):
        params = {"chainid": self.chainid, **params}

        def fetch():
            for attempt in range(6):
                self.limit.wait()
                try:
                    body = requests.get(self.API, params={**params, "apikey": self.key}, timeout=60).json()
                except (requests.RequestException, ValueError):
                    time.sleep(2 ** attempt)
                    continue
                result = body.get("result")
                if isinstance(result, str) and "rate limit" in result.lower():
                    time.sleep(1 + attempt)
                    continue
                return body
            raise RuntimeError("etherscan rate limited")

        return _cached("etherscan", json.dumps(params, sort_keys=True), fetch)

    def source(self, address: str) -> dict:
        """{'name', 'verified', 'abi', 'proxy', 'implementation'} for a contract."""
        body = self.call(module="contract", action="getsourcecode", address=address)
        r = (body.get("result") or [{}])[0] if isinstance(body.get("result"), list) else {}
        abi = r.get("ABI", "")
        verified = bool(r.get("SourceCode"))
        return {
            "name": r.get("ContractName") or None,
            "verified": verified,
            "abi": json.loads(abi) if verified and abi.startswith("[") else None,
            "proxy": r.get("Proxy") == "1",
            "implementation": r.get("Implementation") or None,
        }

    def creation(self, address: str) -> dict | None:
        body = self.call(module="contract", action="getcontractcreation", contractaddresses=address)
        res = body.get("result")
        return res[0] if isinstance(res, list) and res else None

    def txlist(self, address: str, endblock: int, offset: int = 100, action: str = "txlist") -> list:
        body = self.call(module="account", action=action, address=address, startblock=0, endblock=endblock,
                         page=1, offset=offset, sort="desc")
        res = body.get("result")
        return res if isinstance(res, list) else []


class Prices:
    """Historical USD prices from DefiLlama (no key)."""

    URL = "https://coins.llama.fi/prices/historical/{ts}/{coins}?searchWidth=12h"
    # used only when DefiLlama has no price near the timestamp (it has gaps, e.g. BSC USDT in 2023)
    STABLES = {
        "eth": {"0xdac17f958d2ee523a2206206994597c13d831ec7", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "0x6b175474e89094c44da98b954eedeac495271d0f", "0x4fabb145d64652a948d72533023f6e7a623c7c53"},
        "bsc": {"0x55d398326f99059ff775485246999027b3197955", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
                "0xe9e7cea3dedca5984780bafc599bd69add087d56", "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3",
                "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409"},
        "base": {"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "0x50c5725949a6f0c72e6c4a641f24049a917db0cb"},
        "polygon": {"0x2791bca1f2de4661ed88a30c99a7a9449aa84174", "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
                    "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"},
        "arbitrum": {"0xff970a61a04b1ca14834a43f5de4533ebddb5cc8", "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
                     "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"},
        "optimism": {"0x7f5c764cbc14f9669b88837ca1490cca17c31607", "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
                     "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58", "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"},
    }

    def __init__(self, chain: str = "eth"):
        self.chain = chain
        self.prefix = CHAINS[chain]["llama"]
        self.native = CHAINS[chain]["native"]

    _limit = RateLimiter(2)  # shared across instances in a process; DefiLlama's free API rate-limits hard

    def _get(self, url: str) -> dict:
        """Fetch with throttling and long backoff on 429; raise instead of returning an empty result."""
        for attempt in range(8):
            self._limit.wait()
            try:
                r = requests.get(url, timeout=60)
                if r.status_code == 200:
                    return r.json().get("coins", {})
                if r.status_code == 429:
                    time.sleep(min(15 * (attempt + 1), 90))
                    continue
            except requests.RequestException:
                pass
            time.sleep(2 ** attempt)
        raise RuntimeError("DefiLlama prices unavailable (rate limited)")

    @staticmethod
    def _cache_get(key: str):
        path = CACHE / "prices" / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")
        return json.loads(path.read_text()) if path.exists() else None

    @staticmethod
    def _cache_put(key: str, data: dict):
        path = CACHE / "prices" / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))

    _index: dict | None = None  # coin -> sorted [(observation_ts, price)] from every cached DefiLlama answer

    @classmethod
    def _load_index(cls) -> dict:
        if cls._index is None:
            idx: dict[str, list] = {}
            for f in (CACHE / "prices").glob("*.json"):
                try:
                    d = json.loads(f.read_text())
                except ValueError:
                    continue
                if not isinstance(d, dict) or "price" in d:
                    continue
                for coin, v in d.items():
                    if isinstance(v, dict) and v.get("price") is not None and v.get("timestamp"):
                        idx.setdefault(coin.lower(), []).append((int(v["timestamp"]), float(v["price"])))
            cls._index = {k: sorted(v) for k, v in idx.items()}
        return cls._index

    def _indexed(self, coin: str, ts: int, window: int = 6 * 3600) -> float | None:
        obs = self._load_index().get(coin.lower())
        if not obs:
            return None
        best = min(obs, key=lambda o: (abs(o[0] - ts), o[0] > ts))  # nearest, prefer not-after
        return best[1] if abs(best[0] - ts) <= window else None

    def usd(self, tokens: list[str], ts: int) -> dict[str, float]:
        out: dict[str, float] = {}
        tokens = sorted(set(t.lower() for t in tokens))
        key_of0 = lambda t: self.native if t == "eth" else f"{self.prefix}:{t}"  # noqa: E731
        for t in list(tokens):
            v = self._indexed(key_of0(t), ts)
            if v is not None:
                out[t] = v
                tokens.remove(t)
        key_of = lambda t: self.native if t == "eth" else f"{self.prefix}:{t}"  # noqa: E731
        for i in range(0, len(tokens), 40):
            chunk = tokens[i:i + 40]
            coins = ",".join(key_of(t) for t in chunk)
            data = dict(self._cache_get(f"{ts}:{coins}") or {})  # exact-timestamp results cached earlier
            missing = [t for t in chunk if key_of(t) not in data]
            if missing:
                mcoins = ",".join(key_of(t) for t in missing)
                wide = self._cache_get(f"w12h:{ts}:{mcoins}")
                if wide is None:
                    try:
                        wide = self._get(self.URL.format(ts=ts, coins=mcoins))
                        self._cache_put(f"w12h:{ts}:{mcoins}", wide)  # a successful (possibly empty) answer
                    except RuntimeError:
                        wide = None  # DefiLlama unavailable: use Alchemy for these tokens
                if wide is None:
                    llama_failed = set(missing)
                    wide = {}
                else:
                    llama_failed = set()
                data.update(wide)
            else:
                llama_failed = set()
            for t in chunk:
                k = key_of(t)
                if k in data and data[k].get("price") is not None:
                    out[t] = float(data[k]["price"])
                elif t in llama_failed and (a := self._alchemy_price(t, ts)) is not None:
                    out[t] = a
                elif t in self.STABLES.get(self.chain, ()):
                    out[t] = 1.0
        return out

    _alimit = RateLimiter(5)
    ALCHEMY_NET = {"eth": "eth-mainnet", "bsc": "bnb-mainnet", "base": "base-mainnet", "polygon": "polygon-mainnet",
                   "arb": "arb-mainnet", "arbitrum": "arb-mainnet", "optimism": "opt-mainnet"}
    NATIVE_SYMBOL = {"eth": "ETH", "bsc": "BNB", "base": "ETH", "polygon": "POL", "arbitrum": "ETH", "optimism": "ETH"}

    def _alchemy_price(self, token: str, ts: int) -> float | None:
        """Last hourly price at or before ts (no look-ahead) from Alchemy's Prices API; cached incl. misses."""
        hour = ts - ts % 3600
        key = f"alchemy:{self.chain}:{token}:{hour}"
        cached = self._cache_get(key)
        if cached is not None:
            return cached.get("price")
        import datetime as _dt
        iso = lambda t: _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        body = {"startTime": iso(hour - 6 * 3600), "endTime": iso(hour), "interval": "1h"}
        if token == "eth":
            body["symbol"] = self.NATIVE_SYMBOL[self.chain]
        else:
            body.update({"network": self.ALCHEMY_NET[self.chain], "address": token})
        price = None
        for attempt in range(4):
            self._alimit.wait()
            try:
                r = requests.post(f"https://api.g.alchemy.com/prices/v1/{alchemy_key(1)}/tokens/historical",
                                  json=body, timeout=30)
            except requests.RequestException:
                time.sleep(2 ** attempt)
                continue
            if r.status_code == 429:
                time.sleep(5 * (attempt + 1))
                continue
            if r.status_code == 200:
                pts = [d for d in r.json().get("data", []) if d.get("value") is not None]
                price = float(pts[-1]["value"]) if pts else None
                self._cache_put(key, {"price": price})
            break
        return price


class NftPrices:
    """Daily NFT collection floor prices (in ETH) from DefiLlama's NFT history, read AS OF a timestamp (no look-ahead).
    Coverage: major Ethereum collections from ~2023-03; anything else is unpriced (counts still go on the card)."""

    URL = "https://nft.llama.fi/floorHistory/{coll}"
    _limit = RateLimiter(2)

    def floor_eth(self, collection: str, ts: int, max_age_days: float = 3.0) -> float | None:
        coll = collection.lower()

        def fetch():
            for attempt in range(5):
                self._limit.wait()
                try:
                    r = requests.get(self.URL.format(coll=coll), timeout=60)
                    if r.status_code == 200:
                        body = r.json()
                        return body if isinstance(body, list) else []
                    if r.status_code in (400, 404):
                        return []
                except (requests.RequestException, ValueError):
                    pass
                time.sleep(2 ** attempt)
            raise RuntimeError("DefiLlama NFT history unavailable")

        hist = _cached("nft_floor", coll, fetch)
        import datetime as _dt
        best = None
        for pt in hist:
            try:
                t = _dt.datetime.fromisoformat(pt["timestamp"].replace("Z", "+00:00")).timestamp()
            except (KeyError, ValueError):
                continue
            if t <= ts and pt.get("floorPrice") is not None and (best is None or t > best[0]):
                best = (t, float(pt["floorPrice"]))
        if best and ts - best[0] <= max_age_days * 86400:
            return best[1]
        return None
