"""Validate Kubernetes TokenReview response fields; transport trust is external.

Never accept a response body supplied by the untrusted collector. A trusted
verifier must POST to the API server over authenticated TLS and pass the result.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class TokenReviewResult:
    authenticated: bool
    principal: str | None
    reason: str


def validate_tokenreview(response: dict, *, expected_username: str, expected_uid: str, expected_audience: str) -> TokenReviewResult:
    if not isinstance(response, dict) or response.get('kind') != 'TokenReview' or response.get('apiVersion') != 'authentication.k8s.io/v1':
        return TokenReviewResult(False, None, 'INVALID_TOKENREVIEW_RESPONSE')
    status = response.get('status')
    if not isinstance(status, dict) or status.get('authenticated') is not True:
        return TokenReviewResult(False, None, 'TOKEN_NOT_AUTHENTICATED')
    user = status.get('user')
    if not isinstance(user, dict) or not expected_username or not expected_uid or user.get('username') != expected_username or user.get('uid') != expected_uid:
        return TokenReviewResult(False, None, 'IDENTITY_MISMATCH')
    audiences = status.get('audiences')
    if not isinstance(audiences, list) or not expected_audience or expected_audience not in audiences:
        return TokenReviewResult(False, None, 'AUDIENCE_MISMATCH')
    return TokenReviewResult(True, expected_username, 'TOKENREVIEW_IDENTITY_MATCHED')
