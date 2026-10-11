"""Issue a verifier-owned nonce only to a Kubernetes-authenticated collector.

Caller may supply a bearer token but cannot select principal or execution ID.
"""
from dataclasses import dataclass
import secrets

from cpal.tokenreview_client import authenticate_collector


@dataclass(frozen=True)
class ChallengeIssueResult:
    accepted: bool
    reason: str
    nonce: str | None = None
    execution_id: str | None = None
    expires_at: int | None = None


def issue_authenticated_challenge(*, candidate_token, api_url, cluster_ca, verifier_token, expected_username, expected_uid, audience, challenge_store, now=None):
    if not isinstance(candidate_token, str) or not candidate_token.strip():
        return ChallengeIssueResult(False, 'MISSING_BEARER_TOKEN')
    authentication = authenticate_collector(api_url=api_url, cluster_ca=cluster_ca, verifier_token=verifier_token, candidate_token=candidate_token, expected_username=expected_username, expected_uid=expected_uid, audience=audience)
    if not authentication.authenticated:
        return ChallengeIssueResult(False, 'COLLECTOR_NOT_AUTHENTICATED')
    execution_id = secrets.token_urlsafe(24)
    try:
        challenge = challenge_store.issue(principal=expected_username, execution_id=execution_id, now=now)
    except (OSError, ValueError):
        return ChallengeIssueResult(False, 'CHALLENGE_STORE_UNAVAILABLE')
    return ChallengeIssueResult(True, 'CHALLENGE_ISSUED', challenge.nonce, challenge.execution_id, challenge.expires_at)
