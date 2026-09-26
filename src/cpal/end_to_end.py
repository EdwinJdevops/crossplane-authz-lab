from __future__ import annotations
from dataclasses import dataclass
from .access_requirements import EffectiveAccessAssessment, RequirementStatus
from .aws_evidence import Assurance, AwsEvidenceResult
from .k8s_graph import GraphResult
from .model import Decision

@dataclass(frozen=True)
class EndToEndResult:
    decision: Decision
    reason: str

def evaluate_protected_data_invariant(graph: GraphResult, network: AwsEvidenceResult, data_access: EffectiveAccessAssessment) -> EndToEndResult:
    """Evaluate: an internet-reachable workload must not have protected-data read access."""
    if graph.unknowns:
        return EndToEndResult(Decision.INSUFFICIENT_EVIDENCE,"Kubernetes identity path is incomplete: "+"; ".join(graph.unknowns))
    if not any(e.relation=="assumes_role" for e in graph.edges):
        return EndToEndResult(Decision.INSUFFICIENT_EVIDENCE,"Kubernetes-to-AWS identity edge is not proven")
    if network.assurance is Assurance.UNKNOWN:
        return EndToEndResult(Decision.INSUFFICIENT_EVIDENCE,"network reachability is unresolved")
    if data_access.status is RequirementStatus.UNKNOWN:
        return EndToEndResult(Decision.INSUFFICIENT_EVIDENCE,"protected-data authorization is unresolved")
    internet_reachable=network.assurance is Assurance.PROVEN
    can_read=data_access.status is RequirementStatus.SATISFIED
    if internet_reachable and can_read:
        return EndToEndResult(Decision.DENY,"proven internet reachability composes with satisfied protected-data access")
    return EndToEndResult(Decision.ALLOW,"available authoritative evidence does not produce the forbidden composition")
