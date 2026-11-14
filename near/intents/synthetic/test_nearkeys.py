"""Tests for the pure-Python NEAR signing helpers used to drive the sandbox."""

import hashlib
import unittest

from near.intents.synthetic import nearkeys


class Ed25519Test(unittest.TestCase):
    # RFC 8032 section 7.1, TEST 1 and TEST 2
    def test_rfc8032_vector_1(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.assertEqual(
            nearkeys.ed25519_public_key(seed).hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        self.assertEqual(
            nearkeys.ed25519_sign(seed, b"").hex(),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )

    def test_rfc8032_vector_2(self):
        seed = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        self.assertEqual(
            nearkeys.ed25519_sign(seed, bytes([0x72])).hex(),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        )


class Base58Test(unittest.TestCase):
    def test_roundtrip_and_leading_zeros(self):
        raw = b"\x00\x00" + hashlib.sha256(b"x").digest()
        self.assertEqual(nearkeys.b58decode(nearkeys.b58encode(raw)), raw)
        self.assertTrue(nearkeys.b58encode(raw).startswith("11"))

    def test_known_value(self):
        self.assertEqual(nearkeys.b58encode(b"hello world"), "StV1DL6CwTryKyV")


class KeyPairTest(unittest.TestCase):
    def test_near_secret_key_string_roundtrip(self):
        kp = nearkeys.KeyPair.from_seed(b"\x01" * 32)
        again = nearkeys.KeyPair.from_secret_key(kp.secret_key_str)
        self.assertEqual(again.public_key_str, kp.public_key_str)
        self.assertTrue(kp.public_key_str.startswith("ed25519:"))

    def test_implicit_account_is_hex_of_public_key(self):
        kp = nearkeys.KeyPair.from_seed(b"\x02" * 32)
        self.assertEqual(kp.implicit_account_id, kp.public_key.hex())
        self.assertEqual(len(kp.implicit_account_id), 64)


class BorshTransactionTest(unittest.TestCase):
    def test_transfer_transaction_layout(self):
        kp = nearkeys.KeyPair.from_seed(b"\x03" * 32)
        block_hash = bytes(range(32))
        tx = nearkeys.serialize_transaction(
            signer_id="a.near",
            public_key=kp.public_key,
            nonce=7,
            receiver_id="b.near",
            block_hash=block_hash,
            actions=[nearkeys.transfer(10)],
        )
        expected = (
            (6).to_bytes(4, "little") + b"a.near"
            + b"\x00" + kp.public_key
            + (7).to_bytes(8, "little")
            + (6).to_bytes(4, "little") + b"b.near"
            + block_hash
            + (1).to_bytes(4, "little")
            + b"\x03" + (10).to_bytes(16, "little")
        )
        self.assertEqual(tx, expected)

    def test_function_call_action_layout(self):
        action = nearkeys.function_call("m", b"{}", gas=5, deposit=1)
        self.assertEqual(
            action,
            b"\x02" + (1).to_bytes(4, "little") + b"m" + (2).to_bytes(4, "little") + b"{}"
            + (5).to_bytes(8, "little") + (1).to_bytes(16, "little"),
        )

    def test_signed_transaction_signature_verifies_hash(self):
        kp = nearkeys.KeyPair.from_seed(b"\x04" * 32)
        tx = nearkeys.serialize_transaction("a.near", kp.public_key, 1, "b.near", bytes(32),
                                            [nearkeys.transfer(1)])
        signed, tx_hash = nearkeys.sign_transaction(kp, tx)
        self.assertEqual(tx_hash, hashlib.sha256(tx).digest())
        self.assertEqual(signed[: len(tx)], tx)
        self.assertEqual(signed[len(tx)], 0)
        self.assertEqual(signed[len(tx) + 1:], nearkeys.ed25519_sign(kp.seed, tx_hash))


if __name__ == "__main__":
    unittest.main()
