"""Minimal NEAR transaction signing in pure Python (stdlib only).

The project venv has no ed25519 or borsh package, and pyproject.toml must not change, so this module implements the
small subset the sandbox driver needs: RFC 8032 ed25519 signing, base58, NEAR key strings, and borsh encoding of a
`Transaction` (V0) with the actions the scenarios use.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

# ---------------------------------------------------------------------------------------------------------------------
# ed25519 (RFC 8032), extended twisted Edwards coordinates
# ---------------------------------------------------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int:
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if x & 1 != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(s: int, point):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _point_add(q, point)
        point = _point_add(point, point)
        s >>= 1
    return q


def _encode_point(point) -> bytes:
    x, y, z, _ = point
    zinv = pow(z, _P - 2, _P)
    x, y = x * zinv % _P, y * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _expand_seed(seed: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public_key(seed: bytes) -> bytes:
    a, _ = _expand_seed(seed)
    return _encode_point(_scalar_mult(a, _G))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _expand_seed(seed)
    public = _encode_point(_scalar_mult(a, _G))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    big_r = _encode_point(_scalar_mult(r, _G))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % _L
    s = (r + k * a) % _L
    return big_r + int.to_bytes(s, 32, "little")


# ---------------------------------------------------------------------------------------------------------------------
# base58 (bitcoin alphabet, as NEAR uses)
# ---------------------------------------------------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + body


# ---------------------------------------------------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class KeyPair:
    seed: bytes
    public_key: bytes

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        return cls(seed=seed, public_key=ed25519_public_key(seed))

    @classmethod
    def from_secret_key(cls, secret: str) -> "KeyPair":
        raw = b58decode(secret.removeprefix("ed25519:"))
        return cls.from_seed(raw[:32])

    @property
    def secret_key_str(self) -> str:
        return "ed25519:" + b58encode(self.seed + self.public_key)

    @property
    def public_key_str(self) -> str:
        return "ed25519:" + b58encode(self.public_key)

    @property
    def implicit_account_id(self) -> str:
        return self.public_key.hex()


# ---------------------------------------------------------------------------------------------------------------------
# borsh: Transaction V0 and actions
# ---------------------------------------------------------------------------------------------------------------------


def _u32(n: int) -> bytes:
    return n.to_bytes(4, "little")


def _u64(n: int) -> bytes:
    return n.to_bytes(8, "little")


def _u128(n: int) -> bytes:
    return n.to_bytes(16, "little")


def _string(s: str) -> bytes:
    raw = s.encode()
    return _u32(len(raw)) + raw


def _bytes(b: bytes) -> bytes:
    return _u32(len(b)) + b


def _public_key(pk: bytes) -> bytes:
    return b"\x00" + pk


def create_account() -> bytes:
    return b"\x00"


def deploy_contract(code: bytes) -> bytes:
    return b"\x01" + _bytes(code)


def function_call(method: str, args: bytes, gas: int, deposit: int = 0) -> bytes:
    return b"\x02" + _string(method) + _bytes(args) + _u64(gas) + _u128(deposit)


def transfer(amount: int) -> bytes:
    return b"\x03" + _u128(amount)


def add_full_access_key(public_key: bytes) -> bytes:
    # AccessKey { nonce: u64, permission: FullAccess (enum variant 1) }
    return b"\x05" + _public_key(public_key) + _u64(0) + b"\x01"


def serialize_transaction(signer_id: str, public_key: bytes, nonce: int, receiver_id: str, block_hash: bytes,
                          actions: list[bytes]) -> bytes:
    return (_string(signer_id) + _public_key(public_key) + _u64(nonce) + _string(receiver_id) + block_hash
            + _u32(len(actions)) + b"".join(actions))


def sign_transaction(key: KeyPair, tx: bytes) -> tuple[bytes, bytes]:
    """Return (borsh SignedTransaction, tx hash)."""
    tx_hash = hashlib.sha256(tx).digest()
    return tx + b"\x00" + ed25519_sign(key.seed, tx_hash), tx_hash
