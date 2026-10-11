"""Verifier-controlled local composition; not yet an authenticated network service.

The verifier must own expected identity, challenge and trust configuration.
Never accept these values from an untrusted report as authoritative.
"""

from dataclasses import dataclass

from cpal.report_challenge import validate_report
from cpal.tokenreview_client import authenticate_collector


@dataclass(frozen=True)
class VerifiedReport:
    accepted: bool
    reason: str


def verify_report(*, report: bytes, envelope: dict, candidate_token: str, api_url: str, cluster_ca: str, verifier_token: str, expected_username: str, expected_uid: str, audience: str, expected_nonce: str, expected_execution: str, ledger, now: int) -> VerifiedReport:
    identity = authenticate_collector(api_url=api_url, cluster_ca=cluster_ca, verifier_token=verifier_token, candidate_token=candidate_token, expected_username=expected_username, expected_uid=expected_uid, audience=audience)
    if not identity.authenticated:
        return VerifiedReport(False, 'IDENTITY_' + identity.reason)
    result = validate_report(report, envelope, authenticated_principal=identity.principal, expected_principal=expected_username, expected_nonce=expected_nonce, expected_execution=expected_execution, ledger=ledger, now=now)
    return VerifiedReport(result.accepted, result.reason)
