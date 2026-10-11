"""Verifier-side submission handler; transport security is deployment-owned.

Only call from an authenticated, protected ingress. Candidate bearer tokens
are passed separately from request bodies and never logged or echoed.
"""

from dataclasses import dataclass

from cpal.challenge_verified_report import verify_challenged_report
from cpal.report_protocol import InvalidSubmission, parse_submission


@dataclass(frozen=True)
class SubmissionResponse:
    accepted: bool
    reason: str


def handle_submission(*, body: bytes, bearer_token: str, api_url: str, cluster_ca: str, verifier_token: str, expected_username: str, expected_uid: str, audience: str, challenge_store, now: int) -> SubmissionResponse:
    if not isinstance(bearer_token, str) or not bearer_token:
        return SubmissionResponse(False, 'MISSING_BEARER_TOKEN')
    try:
        report, envelope = parse_submission(body)
    except InvalidSubmission as exc:
        return SubmissionResponse(False, str(exc))
    result = verify_challenged_report(report=report, envelope=envelope, candidate_token=bearer_token, api_url=api_url, cluster_ca=cluster_ca, verifier_token=verifier_token, expected_username=expected_username, expected_uid=expected_uid, audience=audience, challenge_store=challenge_store, now=now)
    return SubmissionResponse(result.accepted, result.reason)
