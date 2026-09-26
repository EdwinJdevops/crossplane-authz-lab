from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .evidence import BoundAuthorization
from .model import Decision


@dataclass(frozen=True)
class FreshnessResult:
    decision: Decision
    reason: str
    changed_subjects: tuple[str, ...] = ()
    missing_subjects: tuple[str, ...] = ()


def evaluate_authorization_freshness(
    authorization: BoundAuthorization,
    current_state_digests: Mapping[str, str],
    operation_digest: str,
) -> FreshnessResult:
    """Validate only the state on which authorization actually depended.

    Unrelated state changes do not invalidate the authorization.
    A missing bound subject is UNKNOWN, not a mismatch and never ALLOW.
    """
    authorization.validate()

    if operation_digest != authorization.operation_digest:
        return FreshnessResult(
            Decision.DENY,
            "operation differs from the operation that was authorized",
        )

    missing = tuple(
        sorted(item.subject for item in authorization.evidence if item.subject not in current_state_digests)
    )
    if missing:
        return FreshnessResult(
            Decision.INSUFFICIENT_EVIDENCE,
            "current state is unavailable for one or more bound subjects",
            missing_subjects=missing,
        )

    changed = tuple(
        sorted(
            item.subject
            for item in authorization.evidence
            if current_state_digests[item.subject] != item.state_digest
        )
    )
    if changed:
        return FreshnessResult(
            Decision.DENY,
            "material state changed after authorization",
            changed_subjects=changed,
        )

    return FreshnessResult(Decision.ALLOW, "all bound state remains unchanged")
