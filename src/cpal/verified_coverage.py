from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .coverage import DependencyCoverage
from .k8s_graph import EdgeStatus, derive_kubernetes_identity_graph


@dataclass(frozen=True)
class CoverageAssessment:
    coverage: DependencyCoverage
    reasons: tuple[str, ...]


def assess_e1_coverage(
    kubernetes_objects: list[dict[str, Any]],
    service_name: str,
    namespace: str,
    *,
    verified_network_subjects: Iterable[str] = (),
    verified_data_subjects: Iterable[str] = (),
) -> CoverageAssessment:
    """Conservative E1 evidence gate, not a proof of full cloud closure.

    The supplied external subject sets must be produced by independently
    verified adapters. Empty sets fail closed. Even with both present, this
    assessment cannot certify full effective AWS authorization, so it never
    asserts complete=True. This prevents callers using the function as a
    production ALLOW oracle before network and IAM proof adapters exist.
    """
    graph = derive_kubernetes_identity_graph(kubernetes_objects, service_name, namespace)
    network = frozenset(verified_network_subjects)
    data = frozenset(verified_data_subjects)
    subjects = {edge.source for edge in graph.edges} | {edge.target for edge in graph.edges}
    subjects.update(network)
    subjects.update(data)
    unknowns = list(graph.unknowns)
    if not graph.edges:
        unknowns.append('workload identity graph has no verified edges')
    if not any(edge.relation == 'assumes_role' and edge.status == EdgeStatus.PROVEN for edge in graph.edges):
        unknowns.append('no supported workload-to-role graph path')
    if not network:
        unknowns.append('no independently verified network evidence')
    if not data:
        unknowns.append('no independently verified effective data authorization evidence')
    unknowns.append('effective AWS authorization and network dependency closure not independently established')
    return CoverageAssessment(
        DependencyCoverage(frozenset(subjects), tuple(sorted(set(unknowns))), complete=False),
        ('Kubernetes object relationships are derived from supplied manifests, not live cluster state',
         'IRSA role annotation does not prove successful STS role assumption',
         'Network and IAM coverage cannot be declared complete from subject identifiers alone'),
    )
