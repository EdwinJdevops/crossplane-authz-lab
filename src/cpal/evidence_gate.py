"""Fail-closed decision gate for externally authenticated evidence.

This module does NOT authenticate collector identities or authorize mutations.
The caller must supply an independently verified identity binding.
"""

from dataclasses import dataclass

from cpal.attestation import verify_with_ledger


@dataclass(frozen=True)
class CollectorIdentity:
    principal: str
    authenticated: bool
    source: str


@dataclass(frozen=True)
class EvidenceDecision:
    accepted: bool
    reason: str


def evaluate_evidence(payload, signature, secret, *, identity: CollectorIdentity | None, expected_principal: str, ledger, execution_id: str, state_digest: str, policy_digest: str, nonce: str, now: int | None = None) -> EvidenceDecision:
    if identity is None or not identity.authenticated or not identity.principal or not identity.source:
        return EvidenceDecision(False, 'UNAUTHENTICATED_COLLECTOR')
    if identity.principal != expected_principal or payload.get('collector') != expected_principal:
        return EvidenceDecision(False, 'COLLECTOR_IDENTITY_MISMATCH')
    # Identity assertions are not trusted merely because they are instances of this dataclass.
    # Production callers MUST establish the identity via an independent trusted verifier.
    verification = verify_with_ledger(payload, signature, secret, ledger=ledger, execution_id=execution_id, state_digest=state_digest, policy_digest=policy_digest, nonce=nonce, now=now)
    if not verification.accepted:
        return EvidenceDecision(False, verification.reason)
    return EvidenceDecision(True, 'LOCAL_EVIDENCE_VALID_IDENTITY_ASSERTED')
