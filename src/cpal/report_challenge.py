"""Report challenge validation primitive, not a collector identity verifier.

Only call after independent authentication of the reporting transport/session.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class ReportResult:
    accepted: bool
    reason: str


def report_digest(report: bytes) -> str:
    if not isinstance(report, bytes):
        raise TypeError('Report must be bytes')
    return hashlib.sha256(report).hexdigest()


def validate_report(report: bytes, envelope: dict, *, authenticated_principal: str | None, expected_principal: str, expected_nonce: str, expected_execution: str, ledger, now: int) -> ReportResult:
    if not authenticated_principal or not hmac.compare_digest(authenticated_principal, expected_principal):
        return ReportResult(False, 'UNAUTHENTICATED_OR_WRONG_PRINCIPAL')
    if not isinstance(report, bytes) or not isinstance(envelope, dict):
        return ReportResult(False, 'INVALID_REPORT')
    required = {'principal', 'nonce', 'execution_id', 'report_sha256', 'expires_at'}
    if set(envelope) != required:
        return ReportResult(False, 'INVALID_ENVELOPE')
    if any(not isinstance(envelope[k], str) for k in required - {'expires_at'}) or type(envelope['expires_at']) is not int:
        return ReportResult(False, 'INVALID_ENVELOPE')
    if envelope['principal'] != expected_principal or envelope['nonce'] != expected_nonce or envelope['execution_id'] != expected_execution:
        return ReportResult(False, 'CHALLENGE_BINDING_MISMATCH')
    if envelope['expires_at'] <= now or envelope['expires_at'] > now + 300:
        return ReportResult(False, 'CHALLENGE_EXPIRED_OR_TOO_LONG')
    if not hmac.compare_digest(envelope['report_sha256'], report_digest(report)):
        return ReportResult(False, 'REPORT_DIGEST_MISMATCH')
    try:
        consumed = ledger.consume(expected_nonce, envelope['expires_at'], now)
    except Exception:
        return ReportResult(False, 'REPLAY_STORE_UNAVAILABLE')
    if not consumed:
        return ReportResult(False, 'REPLAY_DETECTED')
    return ReportResult(True, 'REPORT_BOUND_TO_ASSERTED_SESSION')
