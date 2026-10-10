"""Parse Kubernetes API objects for state observations, not authorization.

Input dictionaries are NOT authenticated. Production collectors must obtain
these from an authenticated Kubernetes API client, with scoped RBAC and
execution-bound transport. ResourceVersion is an opaque concurrency token,
not a timestamp or a globally ordered version across independent objects.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any


@dataclass(frozen=True)
class WorkloadIdentityObservation:
    namespace: str
    pod_name: str
    pod_uid: str
    pod_resource_version: str
    service_account_name: str
    service_account_uid: str
    service_account_resource_version: str
    authenticated: bool = False


def extract_workload_identity(pod: Mapping[str, Any], service_account: Mapping[str, Any]) -> WorkloadIdentityObservation:
    """Reject mismatches and incomplete identity fields; never infer trust."""
    pod_meta = pod.get('metadata')
    pod_spec = pod.get('spec')
    sa_meta = service_account.get('metadata')
    if not isinstance(pod_meta, dict) or not isinstance(pod_spec, dict) or not isinstance(sa_meta, dict):
        raise ValueError('missing Kubernetes object metadata or pod spec')
    namespace = pod_meta.get('namespace')
    sa_name = pod_spec.get('serviceAccountName', 'default')
    required = (namespace, pod_meta.get('name'), pod_meta.get('uid'), pod_meta.get('resourceVersion'),
                sa_name, sa_meta.get('uid'), sa_meta.get('resourceVersion'))
    if any(not isinstance(value, str) or not value.strip() for value in required):
        raise ValueError('missing Kubernetes identity or resourceVersion')
    if sa_meta.get('namespace') != namespace or sa_meta.get('name') != sa_name:
        raise ValueError('pod and service account identity mismatch')
    return WorkloadIdentityObservation(namespace, pod_meta['name'], pod_meta['uid'],
                                       pod_meta['resourceVersion'], sa_name, sa_meta['uid'],
                                       sa_meta['resourceVersion'], False)
