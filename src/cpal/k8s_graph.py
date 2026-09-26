from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any

class EdgeStatus(str, Enum):
    PROVEN = "PROVEN"
    UNKNOWN = "UNKNOWN"

@dataclass(frozen=True)
class Edge:
    source: str
    relation: str
    target: str
    status: EdgeStatus
    evidence: str

@dataclass(frozen=True)
class GraphResult:
    edges: tuple[Edge, ...]
    unknowns: tuple[str, ...]

def _id(obj: dict[str, Any]) -> str:
    md=obj.get("metadata") or {}
    return f"k8s:{md.get('namespace','default')}:{obj.get('kind','?')}:{md.get('name','?')}"

def _labels_match(selector: dict[str,str], labels: dict[str,str]) -> bool:
    return bool(selector) and all(labels.get(k)==v for k,v in selector.items())

def derive_kubernetes_identity_graph(objects: list[dict[str,Any]], service_name: str, namespace: str="default") -> GraphResult:
    services=[o for o in objects if o.get("kind")=="Service" and (o.get("metadata") or {}).get("name")==service_name and (o.get("metadata") or {}).get("namespace","default")==namespace]
    workloads=[o for o in objects if o.get("kind") in {"Deployment","StatefulSet","DaemonSet"} and (o.get("metadata") or {}).get("namespace","default")==namespace]
    accounts=[o for o in objects if o.get("kind")=="ServiceAccount" and (o.get("metadata") or {}).get("namespace","default")==namespace]
    edges=[]; unknowns=[]
    if len(services)!=1:
        return GraphResult((),(f"expected exactly one Service {namespace}/{service_name}",))
    svc=services[0]; selector=(svc.get("spec") or {}).get("selector") or {}
    if not selector:
        unknowns.append(f"Service {namespace}/{service_name} has no selector")
    matched=[]
    for w in workloads:
        template=((w.get("spec") or {}).get("template") or {})
        labels=(template.get("metadata") or {}).get("labels") or {}
        if _labels_match(selector,labels):
            matched.append(w)
            edges.append(Edge(_id(svc),"selects",_id(w),EdgeStatus.PROVEN,"Service selector matches pod-template labels"))
    if selector and not matched:
        unknowns.append(f"Service {namespace}/{service_name} selector matches no supported workload")
    for w in matched:
        podspec=(((w.get("spec") or {}).get("template") or {}).get("spec") or {})
        sa=podspec.get("serviceAccountName","default")
        found=[a for a in accounts if (a.get("metadata") or {}).get("name")==sa]
        if len(found)!=1:
            unknowns.append(f"{_id(w)} references ServiceAccount {namespace}/{sa} without exactly one supplied object")
            continue
        account=found[0]
        edges.append(Edge(_id(w),"uses_identity",_id(account),EdgeStatus.PROVEN,"pod template serviceAccountName"))
        role=((account.get("metadata") or {}).get("annotations") or {}).get("eks.amazonaws.com/role-arn")
        if not isinstance(role,str) or not role:
            unknowns.append(f"{_id(account)} has no IRSA role annotation")
            continue
        edges.append(Edge(_id(account),"assumes_role",f"aws-role:{role}",EdgeStatus.PROVEN,"IRSA role annotation"))
    return GraphResult(tuple(edges),tuple(sorted(unknowns)))
