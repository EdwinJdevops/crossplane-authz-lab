"""Scoped AWS state observations; NOT a complete authorization snapshot.

Clients must be constructed by a trusted runner. Caller-supplied clients or
serialized results are not authenticated evidence. In particular, IAM inline
policy and S3 object metadata do not cover SCPs, resource policies, KMS,
permission boundaries, endpoint policies, session policies or Kubernetes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


@dataclass(frozen=True)
class AwsScopedSnapshot:
    role_arn: str
    bucket: str
    key: str
    inline_policy_digest: str
    object_metadata_digest: str | None
    object_observation: str
    complete: bool = False


def collect_scoped_state(iam: Any, s3: Any, *, role_name: str, bucket: str, key: str) -> AwsScopedSnapshot:
    """Read exact role inline policies and object metadata; fail on API errors.

    `complete` remains False: the observed fields are not the full set of
    effective authorization dependencies. No caller should infer ALLOW.
    """
    role = iam.get_role(RoleName=role_name)['Role']
    arn = role['Arn']
    if not arn.startswith('arn:') or ':role/' not in arn:
        raise ValueError('invalid role ARN returned by AWS')
    policy_names = []
    marker = None
    while True:
        args = {'RoleName': role_name}
        if marker:
            args['Marker'] = marker
        page = iam.list_role_policies(**args)
        policy_names.extend(page.get('PolicyNames', []))
        if not page.get('IsTruncated', False):
            break
        marker = page.get('Marker')
        if not marker:
            raise ValueError('truncated IAM policy list without marker')
    if len(policy_names) != len(set(policy_names)):
        raise ValueError('duplicate IAM policy names')
    policies = {name: iam.get_role_policy(RoleName=role_name, PolicyName=name)['PolicyDocument']
                for name in sorted(policy_names)}
    policy_digest = _digest({'role_arn': arn, 'inline_policies': policies})
    try:
        metadata = s3.head_object(Bucket=bucket, Key=key)
    except Exception:
        # A failure cannot establish object absence or policy denial.
        raise
    fields = {name: metadata.get(name) for name in ('ETag', 'VersionId', 'ContentLength', 'LastModified')}
    return AwsScopedSnapshot(arn, bucket, key, policy_digest,
                             _digest({'bucket': bucket, 'key': key, 'metadata': fields}),
                             'HEAD_SUCCEEDED', False)
