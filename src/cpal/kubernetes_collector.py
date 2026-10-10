"""Read a Pod and its ServiceAccount from a configured Kubernetes API client.

The caller is responsible for TLS verification, kubeconfig/credential security,
RBAC and execution provenance. This module cannot authenticate its own caller
or prove the objects are mutually atomic. It returns unauthenticated evidence.
"""
from __future__ import annotations

from typing import Any

from .kubernetes_state import WorkloadIdentityObservation, extract_workload_identity


def collect_pod_service_account(core_v1: Any, *, namespace: str, pod_name: str) -> WorkloadIdentityObservation:
    if not namespace or not namespace.strip() or not pod_name or not pod_name.strip():
        raise ValueError('namespace and pod_name are required')
    pod = core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
    pod_dict = pod.to_dict() if hasattr(pod, 'to_dict') else pod
    if not isinstance(pod_dict, dict):
        raise ValueError('unexpected Kubernetes pod response')
    meta = pod_dict.get('metadata') or {}
    spec = pod_dict.get('spec') or {}
    if meta.get('namespace') != namespace or meta.get('name') != pod_name:
        raise ValueError('returned pod identity differs from request')
    account_name = spec.get('serviceAccountName') or spec.get('service_account_name') or 'default'
    service_account = core_v1.read_namespaced_service_account(name=account_name, namespace=namespace)
    sa_dict = service_account.to_dict() if hasattr(service_account, 'to_dict') else service_account
    if not isinstance(sa_dict, dict):
        raise ValueError('unexpected Kubernetes service account response')
    # Kubernetes Python client to_dict uses snake_case keys; normalize only
    # the fields consumed by the structural parser.
    def normalize(obj: dict, is_pod: bool) -> dict:
        m = obj.get('metadata') or {}
        normalized = {'metadata': {
            'namespace': m.get('namespace'), 'name': m.get('name'),
            'uid': m.get('uid'), 'resourceVersion': m.get('resourceVersion') or m.get('resource_version')}}
        if is_pod:
            s = obj.get('spec') or {}
            normalized['spec'] = {'serviceAccountName': s.get('serviceAccountName') or s.get('service_account_name') or 'default'}
        return normalized
    return extract_workload_identity(normalize(pod_dict, True), normalize(sa_dict, False))
