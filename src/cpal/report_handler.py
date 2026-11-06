"""Verifier-side submission handler; transport security is deployment-owned.

Only call from an authenticated, protected ingress. Candidate bearer tokens
are passed separately from request bodies and never logged or echoed.
"""

from dataclasses import dataclass

from cpal.aws_identity import verify_identity
from cpal.challenge_verified_report import verify_challenged_report
from cpal.independent_pod_observation import verify_pod_observation
from cpal.report_protocol import InvalidSubmission, parse_submission


@dataclass(frozen=True)
class SubmissionResponse:
    accepted: bool
    reason: str


def handle_submission(*, body: bytes, bearer_token: str, api_url: str, cluster_ca: str, verifier_token: str, expected_username: str, expected_uid: str, audience: str, challenge_store, now: int | None, observation_namespace: str | None = None, observation_pod: str | None = None, sts=None, expected_aws_account=None, expected_aws_arn=None) -> SubmissionResponse:
    if not isinstance(bearer_token, str) or not bearer_token:
        return SubmissionResponse(False, 'MISSING_BEARER_TOKEN')
    try:
        report, envelope = parse_submission(body)
    except InvalidSubmission as exc:
        return SubmissionResponse(False, str(exc))
    crossplane = any(value is not None for value in (sts, expected_aws_account, expected_aws_arn))

    def check_evidence(report, execution):
        if crossplane:
            if sts is None or not observation_namespace or not observation_pod:
                return 'MISSING_CROSSPLANE_CONFIGURATION'
            try:
                matched = verify_identity(sts, expected_account=expected_aws_account, expected_arn=expected_aws_arn)
            except Exception:
                return 'STS_IDENTITY_UNAVAILABLE'
            if not matched:
                return 'STS_IDENTITY_MISMATCH'
        if crossplane or observation_namespace is not None or observation_pod is not None:
            if not verify_pod_observation(report=report, api_url=api_url, cluster_ca=cluster_ca, verifier_token=verifier_token, namespace=observation_namespace, pod_name=observation_pod, execution_id=execution):
                return 'INDEPENDENT_OBSERVATION_MISMATCH'
        return None

    result = verify_challenged_report(report=report, envelope=envelope, candidate_token=bearer_token, api_url=api_url, cluster_ca=cluster_ca, verifier_token=verifier_token, expected_username=expected_username, expected_uid=expected_uid, audience=audience, challenge_store=challenge_store, now=now, check_evidence=check_evidence)
    return SubmissionResponse(result.accepted, result.reason)
