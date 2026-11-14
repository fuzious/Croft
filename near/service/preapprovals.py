"""Operator-authorized, short-lived approvals for exact guarded-router payments."""
import base64
import binascii
import hmac
import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import blocklist

router = APIRouter()
ACCOUNT_ID = r"^(([a-z0-9]+[-_])*[a-z0-9]+\.)*([a-z0-9]+[-_])*[a-z0-9]+$"
MAX_TTL_SECONDS = 900


class PreapprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    consumer_id: str = Field(min_length=2, max_length=64, pattern=ACCOUNT_ID)
    agent_id: str = Field(min_length=2, max_length=64, pattern=ACCOUNT_ID)
    receiver_id: str = Field(min_length=2, max_length=64, pattern=ACCOUNT_ID)
    amount: str = Field(pattern=r"^[1-9][0-9]{0,38}$")
    nonce: str = Field(pattern=r"^(0|[1-9][0-9]{0,19})$")
    ttl_seconds: int = Field(default=300, ge=1, le=MAX_TTL_SECONDS, strict=True)

    @field_validator("amount", "nonce")
    @classmethod
    def fits_integer(cls, value, info):
        bits = 128 if info.field_name == "amount" else 64
        if int(value) >= 2**bits:
            raise ValueError(f"must fit in u{bits}")
        return value


def signing_message(oracle_id: str, req: PreapprovalRequest, proof: dict) -> bytes:
    # Fixed order and newline-delimited validated scalars; identical to the contract.
    return "\n".join([
        "security-oracle:preapproval:v1", oracle_id, req.consumer_id, req.agent_id,
        req.receiver_id, req.amount, req.nonce, proof["key_generation"],
        proof["issued_at_ns"], proof["expires_at_ns"],
    ]).encode("ascii")


@router.post("/v1/preapprovals")
def issue_preapproval(req: PreapprovalRequest, authorization: str | None = Header(None)):
    """Calling this endpoint with the operator token explicitly approves this payment."""
    token = os.environ.get("ORACLE_ADMIN_TOKEN")
    if not token or not hmac.compare_digest((authorization or "").encode(), f"Bearer {token}".encode()):
        raise HTTPException(403, "pre-approval requires the operator token (ORACLE_ADMIN_TOKEN)")
    try:
        oracle_id = os.environ["ORACLE_CONTRACT_ID"]
        # Reuse account validation for configuration as well as untrusted input.
        PreapprovalRequest(consumer_id=oracle_id, agent_id=req.agent_id,
                           receiver_id=req.receiver_id, amount=req.amount, nonce=req.nonce)
        key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(
            os.environ["ORACLE_PREAPPROVAL_SEED_BASE64"], validate=True))
        generation = int(os.environ.get("ORACLE_PREAPPROVAL_KEY_GENERATION", "1"))
        if not 0 < generation < 2**64:
            raise ValueError("invalid generation")
    except (KeyError, ValueError, binascii.Error):
        raise HTTPException(503, "pre-approval signing is not configured correctly") from None
    try:
        blocked = blocklist.lookup(req.receiver_id)["blocked"]
    except (OSError, ValueError):
        raise HTTPException(503, "blocklist unavailable") from None
    if blocked:
        raise HTTPException(409, "receiver is blocked")
    now = time.time_ns()
    proof = {"nonce": req.nonce, "key_generation": str(generation),
             "issued_at_ns": str(now), "expires_at_ns": str(now + req.ttl_seconds * 1_000_000_000)}
    proof["signature"] = base64.b64encode(key.sign(signing_message(oracle_id, req, proof))).decode()
    return {
        "oracle_id": oracle_id,
        "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "verify_args": {"consumer_id": req.consumer_id, "agent_id": req.agent_id,
                        "receiver_id": req.receiver_id, "amount": req.amount, "preapproval": proof},
        "pay_args": {"receiver_id": req.receiver_id, "amount": req.amount, "preapproval": proof},
    }
