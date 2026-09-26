from __future__ import annotations

from dataclasses import dataclass

from .model import Decision, WorkloadState

PROTECTED_DATA = "protected-s3"


@dataclass(frozen=True)
class StrongBaselineResult:
    decision: Decision
    reason: str


def evaluate_central_policy(state: WorkloadState) -> StrongBaselineResult:
    """Model the strongest fair baseline: a central policy receives both facts.

    This represents what OPA or an equivalent policy engine can do when the
    deployment gate is supplied complete, fresh network and data-access state.

    E1 MUST NOT claim novelty when this evidence is available.
    """
    state.validate()
    if state.internet_reachable is None or state.readable_data is None:
        return StrongBaselineResult(
            Decision.INSUFFICIENT_EVIDENCE,
            "central gate lacks evidence required to evaluate the invariant",
        )
    if state.internet_reachable and PROTECTED_DATA in state.readable_data:
        return StrongBaselineResult(
            Decision.DENY,
            "central policy directly detects the forbidden composition",
        )
    return StrongBaselineResult(Decision.ALLOW, "central policy proves the declared invariant")
