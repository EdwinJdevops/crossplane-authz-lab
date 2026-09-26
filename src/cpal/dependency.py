from __future__ import annotations
from dataclasses import dataclass
from typing import Any

class UnsupportedEvidence(ValueError):
    pass

@dataclass(frozen=True)
class DependencyClosure:
    subjects: frozenset[str]
    reasons: tuple[str, ...]

def _resource_changes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise UnsupportedEvidence("Terraform plan has no resource_changes list")
    return changes

def derive_e1_dependency_closure(terraform_plan: dict[str, Any], kubernetes_objects: list[dict[str, Any]], workload: str) -> DependencyClosure:
    subjects: set[str] = set()
    reasons: list[str] = []
    saw_network = False
    saw_identity = False
    for rc in _resource_changes(terraform_plan):
        rtype, address = rc.get("type"), rc.get("address")
        after = (rc.get("change") or {}).get("after")
        if not isinstance(address, str) or not isinstance(after, dict):
            continue
        if rtype in {"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}:
            subjects.add(f"tf:{address}")
            reasons.append(f"{address}: network reachability evidence")
            saw_network = True
        if rtype in {"aws_iam_role", "aws_iam_role_policy", "aws_iam_policy", "aws_iam_role_policy_attachment"}:
            subjects.add(f"tf:{address}")
            reasons.append(f"{address}: workload data-authorization evidence")
            saw_identity = True

    saw_service = False
    saw_service_account = False
    for obj in kubernetes_objects:
        kind = obj.get("kind")
        metadata = obj.get("metadata") or {}
        name = metadata.get("name")
        namespace = metadata.get("namespace", "default")
        if not isinstance(name, str):
            continue
        if kind == "Service" and name == workload:
            subjects.add(f"k8s:{namespace}:Service:{name}")
            reasons.append(f"Service/{name}: workload exposure evidence")
            saw_service = True
        if kind == "ServiceAccount":
            role = (metadata.get("annotations") or {}).get("eks.amazonaws.com/role-arn")
            if isinstance(role, str) and role:
                subjects.add(f"k8s:{namespace}:ServiceAccount:{name}")
                subjects.add(f"aws-role:{role}")
                reasons.append(f"ServiceAccount/{name}: Kubernetes-to-AWS identity bridge")
                saw_service_account = True

    missing = []
    if not saw_network: missing.append("Terraform network evidence")
    if not saw_identity: missing.append("Terraform IAM evidence")
    if not saw_service: missing.append(f"Kubernetes Service/{workload}")
    if not saw_service_account: missing.append("IRSA ServiceAccount role binding")
    if missing:
        raise UnsupportedEvidence("cannot derive complete E1 closure: " + ", ".join(missing))
    return DependencyClosure(frozenset(subjects), tuple(reasons))
