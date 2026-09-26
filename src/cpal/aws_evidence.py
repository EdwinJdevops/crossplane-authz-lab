from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any

class Assurance(str, Enum):
    PROVEN = "PROVEN"
    DENIED = "DENIED"
    UNKNOWN = "UNKNOWN"

@dataclass(frozen=True)
class AwsEvidenceResult:
    assurance: Assurance
    subject: str
    claim: str
    reason: str
    source: str

def iam_role_s3_evidence(simulation: dict[str, Any], role_arn: str, object_arn: str) -> AwsEvidenceResult:
    """Interpret IAM simulation conservatively for a role -> S3 claim.

    An explicit/implicit deny is useful negative evidence. An allow is not
    promoted to PROVEN because AWS documents simulator/live-environment
    differences and does not support resource-based policy simulation for roles.
    """
    results=simulation.get("EvaluationResults")
    if not isinstance(results,list) or not results:
        return AwsEvidenceResult(Assurance.UNKNOWN,role_arn,f"can read {object_arn}","missing IAM simulation result","iam:SimulatePrincipalPolicy")
    matches=[r for r in results if r.get("EvalActionName")=="s3:GetObject" and r.get("EvalResourceName")==object_arn]
    if len(matches)!=1:
        return AwsEvidenceResult(Assurance.UNKNOWN,role_arn,f"can read {object_arn}","no unique s3:GetObject evaluation for exact resource","iam:SimulatePrincipalPolicy")
    decision=matches[0].get("EvalDecision")
    if decision in {"explicitDeny","implicitDeny"}:
        return AwsEvidenceResult(Assurance.DENIED,role_arn,f"can read {object_arn}",f"IAM simulator returned {decision}","iam:SimulatePrincipalPolicy")
    if decision=="allowed":
        return AwsEvidenceResult(Assurance.UNKNOWN,role_arn,f"can read {object_arn}","identity simulation allows request, but this is not proof of live effective role access including all resource-side/service constraints","iam:SimulatePrincipalPolicy")
    return AwsEvidenceResult(Assurance.UNKNOWN,role_arn,f"can read {object_arn}",f"unrecognized IAM simulation decision: {decision!r}","iam:SimulatePrincipalPolicy")

def reachability_evidence(analysis: dict[str, Any], source: str, destination: str) -> AwsEvidenceResult:
    """Interpret a completed Reachability Analyzer result."""
    status=analysis.get("Status")
    if status!="succeeded":
        return AwsEvidenceResult(Assurance.UNKNOWN,source,f"reaches {destination}",f"network analysis not successfully completed: {status!r}","ec2:StartNetworkInsightsAnalysis")
    reachable=analysis.get("NetworkPathFound")
    if reachable is True:
        return AwsEvidenceResult(Assurance.PROVEN,source,f"reaches {destination}","Reachability Analyzer found a network path","ec2:StartNetworkInsightsAnalysis")
    if reachable is False:
        return AwsEvidenceResult(Assurance.DENIED,source,f"reaches {destination}","Reachability Analyzer found no network path","ec2:StartNetworkInsightsAnalysis")
    return AwsEvidenceResult(Assurance.UNKNOWN,source,f"reaches {destination}","completed analysis omitted NetworkPathFound","ec2:StartNetworkInsightsAnalysis")
