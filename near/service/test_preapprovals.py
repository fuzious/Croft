import base64
import json
import os
import sys
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

from near.service.app import app
from near.service.preapprovals import PreapprovalRequest, signing_message

# Public test-only key, never used by the application by default.
TEST_CONFIG = {"ORACLE_ADMIN_TOKEN": "test-operator", "ORACLE_CONTRACT_ID": "oracle.test.near",
               "ORACLE_PREAPPROVAL_SEED_BASE64": base64.b64encode(bytes(range(32))).decode(),
               "ORACLE_PREAPPROVAL_KEY_GENERATION": "1"}
REQUEST = {"consumer_id": "router.test.near", "agent_id": "agent.test.near",
           "receiver_id": "shop.test.near", "amount": "1000000000000000000000000", "nonce": "0"}


class PreapprovalTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.config = patch.dict(os.environ, TEST_CONFIG)
        self.config.start()
        self.addCleanup(self.config.stop)
        self.blocked = patch("near.service.preapprovals.blocklist.lookup", return_value={"blocked": False})
        self.blocked.start()
        self.addCleanup(self.blocked.stop)

    def issue(self, request=None, token="test-operator"):
        return self.client.post("/v1/preapprovals", json=request or REQUEST,
                                headers={"Authorization": f"Bearer {token}"})

    def test_requires_explicit_operator_authorization(self):
        self.assertEqual(self.issue(token="wrong").status_code, 403)
        with patch.dict(os.environ, {"ORACLE_ADMIN_TOKEN": ""}):
            self.assertEqual(self.issue().status_code, 403)

    def test_signs_exact_payment_and_expiry(self):
        with patch("near.service.preapprovals.time.time_ns", return_value=1000000000000):
            response = self.issue()
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        proof = result["pay_args"]["preapproval"]
        self.assertEqual(proof["expires_at_ns"], "1300000000000")
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(result["public_key"]))
        signature = base64.b64decode(proof["signature"])
        key.verify(signature, signing_message(result["oracle_id"], PreapprovalRequest(**REQUEST), proof))
        for field, value in {"consumer_id": "evil.near", "agent_id": "evil.near", "receiver_id": "evil.near",
                             "amount": "1", "nonce": "1"}.items():
            with self.subTest(field=field), self.assertRaises(InvalidSignature):
                key.verify(signature, signing_message(result["oracle_id"],
                           PreapprovalRequest(**(REQUEST | {field: value})), proof))
        self.assertNotIn(TEST_CONFIG["ORACLE_PREAPPROVAL_SEED_BASE64"], response.text)

    def test_rejects_invalid_scope_amount_nonce_and_ttl(self):
        for field, value in [("amount", "0"), ("amount", str(2**128)), ("amount", "01"),
                             ("nonce", str(2**64)), ("nonce", "-1"), ("ttl_seconds", 901),
                             ("ttl_seconds", 0), ("consumer_id", "bad\nid"), ("extra", True)]:
            with self.subTest(field=field, value=value):
                self.assertEqual(self.issue(REQUEST | {field: value}).status_code, 422)

    def test_unconfigured_signing_and_blocked_receiver_fail_closed(self):
        with patch.dict(os.environ, {"ORACLE_PREAPPROVAL_SEED_BASE64": "invalid"}):
            self.assertEqual(self.issue().status_code, 503)
        with patch("near.service.preapprovals.blocklist.lookup", return_value={"blocked": True}):
            self.assertEqual(self.issue().status_code, 409)
        with patch("near.service.preapprovals.blocklist.lookup", side_effect=OSError):
            self.assertEqual(self.issue().status_code, 503)


if __name__ == "__main__":
    # Rust sandbox tests exercise the actual API, then submit its response to WASM.
    args = json.loads(sys.argv[1])
    config = TEST_CONFIG | {"ORACLE_CONTRACT_ID": args.pop("oracle_id")}
    now = args.pop("now_ns")
    with patch.dict(os.environ, config), patch("near.service.preapprovals.time.time_ns", return_value=now), \
            patch("near.service.preapprovals.blocklist.lookup", return_value={"blocked": False}):
        response = TestClient(app).post("/v1/preapprovals", json=args,
                                        headers={"Authorization": "Bearer test-operator"})
        assert response.status_code == 200, response.text
        print(response.text)
