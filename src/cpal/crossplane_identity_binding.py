"""Fail-closed consistency check for independently verified cross-plane identities.

This checks evidence binding, not the integrity of the upstream verifiers and
never overrides the independent collector attestation release blocker.
"""
from dataclasses import dataclass
import hmac


@dataclass(frozen=True)
class VerifiedAWSIdentity:
    account: str
    arn: str
    execution_id: str
    verified_by_sts: bool


@dataclass(frozen=True)
class VerifiedKubernetesIdentity:
    namespace: str
    pod_uid: str
    execution_id: str
    verified_by_api: bool


@dataclass(frozen=True)
class ExpectedBinding:
    aws_account: str
    aws_arn: str
    namespace: str
    pod_uid: str
    execution_id: str


def identities_bound(aws: VerifiedAWSIdentity | None, kubernetes: VerifiedKubernetesIdentity | None, expected: ExpectedBinding | None) -> bool:
    if not isinstance(aws, VerifiedAWSIdentity) or not isinstance(kubernetes, VerifiedKubernetesIdentity) or not isinstance(expected, ExpectedBinding):
        return False
    if aws.verified_by_sts is not True or kubernetes.verified_by_api is not True:
        return False
    pairs = (
        (aws.account, expected.aws_account),
        (aws.arn, expected.aws_arn),
        (kubernetes.namespace, expected.namespace),
        (kubernetes.pod_uid, expected.pod_uid),
        (aws.execution_id, expected.execution_id),
        (kubernetes.execution_id, expected.execution_id),
    )
    return all(isinstance(left, str) and isinstance(right, str) and 0 < len(left) <= 512 and 0 < len(right) <= 512 and hmac.compare_digest(left, right) for left, right in pairs)
