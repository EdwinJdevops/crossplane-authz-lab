"""Strict cross-plane evidence consistency check (not an authorization grant).

Only accepts observations after their signatures/identities are verified by
separate trusted sources. Never use this function as a production allow gate.
"""
import hmac


REQUIRED = ('execution_id', 'aws_principal_arn', 'aws_resource_arn', 'kubernetes_pod_uid', 'kubernetes_namespace', 'policy_digest')


def consistent(aws, kubernetes, expected):
    if not all(isinstance(item, dict) for item in (aws, kubernetes, expected)):
        return False
    if set(expected) != set(REQUIRED):
        return False
    if any(not isinstance(expected[k], str) or not expected[k] or len(expected[k]) > 512 for k in REQUIRED):
        return False
    for observation in (aws, kubernetes):
        if not all(isinstance(observation.get(k), str) and observation[k] for k in REQUIRED):
            return False
        if not all(hmac.compare_digest(observation[k], expected[k]) for k in REQUIRED):
            return False
    return True
