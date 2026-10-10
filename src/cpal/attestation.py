"""Local verifier prototype. Shared-key MACs do not establish independent collector identity."""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Verification:
    accepted: bool
    reason: str


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sign(payload: dict, secret: bytes) -> str:
    if len(secret) < 32:
        raise ValueError("Secret must have at least 32 bytes")
    return hmac.new(secret, canonical(payload), hashlib.sha256).hexdigest()


def verify(payload: dict, signature: str, secret: bytes, *, execution_id: str, state_digest: str, policy_digest: str, nonce: str, now: int | None = None, consumed_nonces: set[str] | None = None) -> Verification:
    if consumed_nonces is None:
        return Verification(False, "REPLAY_STORE_REQUIRED")
    if len(secret) < 32:
        return Verification(False, "INVALID_VERIFIER_KEY")
    if not isinstance(payload, dict) or set(payload) != {"version", "collector", "execution_id", "state_digest", "policy_digest", "nonce", "issued_at", "expires_at", "observation_digest"}:
        return Verification(False, "INVALID_SCHEMA")
    if payload["version"] != 1 or not all(isinstance(payload[k], str) and payload[k] for k in ("collector", "execution_id", "state_digest", "policy_digest", "nonce", "observation_digest")):
        return Verification(False, "INVALID_FIELDS")
    if type(payload["issued_at"]) is not int or type(payload["expires_at"]) is not int:
        return Verification(False, "INVALID_TIMESTAMPS")
    current = int(time.time()) if now is None else now
    if payload["issued_at"] > current + 30 or payload["expires_at"] <= current or payload["expires_at"] - payload["issued_at"] > 300:
        return Verification(False, "EXPIRED_OR_INVALID_WINDOW")
    if any(payload[k] != v for k, v in (("execution_id", execution_id), ("state_digest", state_digest), ("policy_digest", policy_digest), ("nonce", nonce))):
        return Verification(False, "BINDING_MISMATCH")
    if nonce in consumed_nonces:
        return Verification(False, "REPLAY_DETECTED")
    try:
        expected = sign(payload, secret)
        valid = isinstance(signature, str) and hmac.compare_digest(expected, signature)
    except (TypeError, ValueError, OverflowError):
        return Verification(False, "INVALID_SIGNATURE")
    if not valid:
        return Verification(False, "INVALID_SIGNATURE")
    consumed_nonces.add(nonce)
    return Verification(True, "MAC_VALID_LOCAL_ONLY")


def verify_with_ledger(payload: dict, signature: str, secret: bytes, *, ledger, execution_id: str, state_digest: str, policy_digest: str, nonce: str, now: int | None = None) -> Verification:
    """Verify first, then atomically consume nonce; fail closed on storage errors."""
    current = int(time.time()) if now is None else now
    result = verify(payload, signature, secret, execution_id=execution_id, state_digest=state_digest, policy_digest=policy_digest, nonce=nonce, now=current, consumed_nonces=set())
    if not result.accepted:
        return result
    try:
        if not ledger.consume(nonce, payload['expires_at'], current):
            return Verification(False, 'REPLAY_DETECTED')
    except Exception:
        return Verification(False, 'REPLAY_STORE_UNAVAILABLE')
    return Verification(True, 'MAC_VALID_LOCAL_DURABLE_REPLAY')
