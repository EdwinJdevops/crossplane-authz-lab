from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

class RequirementStatus(str, Enum):
    SATISFIED = "SATISFIED"
    DENIED = "DENIED"
    UNKNOWN = "UNKNOWN"

@dataclass(frozen=True)
class Requirement:
    name: str
    required: bool
    status: RequirementStatus
    source: str

@dataclass(frozen=True)
class EffectiveAccessAssessment:
    status: RequirementStatus
    requirements: tuple[Requirement, ...]
    reason: str

def assess_s3_get_object(requirements: tuple[Requirement, ...]) -> EffectiveAccessAssessment:
    """Compose evidence status without reimplementing AWS policy evaluation."""
    required=[r for r in requirements if r.required]
    if any(r.status is RequirementStatus.DENIED for r in required):
        return EffectiveAccessAssessment(RequirementStatus.DENIED,requirements,"at least one required authorization component is denied")
    missing=[r.name for r in required if r.status is RequirementStatus.UNKNOWN]
    if missing:
        return EffectiveAccessAssessment(RequirementStatus.UNKNOWN,requirements,"required evidence unresolved: "+", ".join(sorted(missing)))
    return EffectiveAccessAssessment(RequirementStatus.SATISFIED,requirements,"all declared authorization requirements are satisfied by authoritative evidence")

def s3_get_object_contract(*, identity, boundary, scp, bucket_policy, rcp, endpoint_policy, kms=None) -> EffectiveAccessAssessment:
    reqs=[
        Requirement("identity-policy",True,identity,"AWS IAM evidence"),
        Requirement("permissions-boundary",True,boundary,"AWS IAM evidence"),
        Requirement("scp",True,scp,"AWS Organizations evidence"),
        Requirement("bucket-policy",True,bucket_policy,"Amazon S3 evidence"),
        Requirement("rcp",True,rcp,"AWS Organizations evidence"),
        Requirement("vpc-endpoint-policy",True,endpoint_policy,"Amazon VPC evidence"),
    ]
    if kms is not None:
        reqs.append(Requirement("kms-decrypt",True,kms,"AWS KMS evidence"))
    return assess_s3_get_object(tuple(reqs))
