"""Best-effort Kubernetes read consistency, not a transactional snapshot.

Two matching reads narrow the observation window but cannot eliminate ABA,
changes after the last read, or unrelated authorization dependencies.
"""
from __future__ import annotations

from typing import Any
from .kubernetes_collector import collect_pod_service_account
from .kubernetes_state import WorkloadIdentityObservation


def collect_stable_identity(core_v1: Any, *, namespace: str, pod_name: str) -> WorkloadIdentityObservation:
    first = collect_pod_service_account(core_v1, namespace=namespace, pod_name=pod_name)
    second = collect_pod_service_account(core_v1, namespace=namespace, pod_name=pod_name)
    if first != second:
        raise ValueError('Kubernetes identity changed during collection')
    # A match is only a best-effort consistency check. No trust upgrade.
    return second
