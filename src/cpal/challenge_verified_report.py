"""Authenticated report validation bound to verifier-owned durable challenge.

Not a network transport: caller must be a trusted verifier endpoint, never
an untrusted collector with access to verifier credentials or challenge DB.
"""

import hashlib
import hmac
from dataclasses import dataclass

from cpal.tokenreview_client import authenticate_collector


@dataclass(frozen=True)
class ChallengeReportDecision:
    accepted: bool
    reason: str


def verify_challenged_report(*, report: bytes, envelope: dict, candidate_token: str, api_url: str, cluster_ca: str, verifier_token: str, expected_username: str, expected_uid: str, audience: str, challenge_store, now: int) -> ChallengeReportDecision:
    identity = authenticate_collector(api_url=api_url, cluster_ca=cluster_ca, verifier_token=verifier_token, candidate_token=candidate_token, expected_username=expected_username, expected_uid=expected_uid, audience=audience)
    if not identity.authenticated or identity.principal != expected_username:
        return ChallengeReportDecision(False, 'IDENTITY_NOT_VERIFIED')
    if not isinstance(report, bytes) or not isinstance(envelope, dict):
        return ChallengeReportDecision(False, 'INVALID_REPORT')
    nonce = envelope.get('nonce')
    execution = envelope.get('execution_id')
    digest = envelope.get('report_sha256')
    if not all(isinstance(x, str) and x for x in (nonce, execution, digest)):
        return ChallengeReportDecision(False, 'INVALID_ENVELOPE')
    if envelope.get('principal') != expected_username:
        return ChallengeReportDecision(False, 'PRINCIPAL_MISMATCH')
    if not hmac.compare_digest(hashlib.sha256(report).hexdigest(), digest):
        return ChallengeReportDecision(False, 'REPORT_DIGEST_MISMATCH')
    try:
        consumed = challenge_store.consume(nonce=nonce, principal=expected_username, execution_id=execution, now=now)
    except Exception:
        return ChallengeReportDecision(False, 'CHALLENGE_STORE_UNAVAILABLE')
    if not consumed:
        return ChallengeReportDecision(False, 'CHALLENGE_NOT_VALID_OR_ALREADY_USED')
    return ChallengeReportDecision(True, 'VERIFIED_CHALLENGE_REPORT')
