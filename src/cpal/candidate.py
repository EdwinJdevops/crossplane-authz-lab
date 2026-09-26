from __future__ import annotations

from dataclasses import dataclass

from .baseline import LocalDecision, evaluate_local_controls
from .model import Decision, WorkloadState


PROTECTED_DATA = "protected-s3"


@dataclass(frozen=True)
class Evaluation:
    decision: Decision
    reason: str
    local_decisions: tuple[LocalDecision, ...]


def evaluate_cross_system_invariant(state: WorkloadState) -> Evaluation:
    """Evaluate the E1 invariant over composed state.

    Invariant:
      a production workload must not be simultaneously internet reachable
      and authorized to read the protected data resource.

    UNKNOWN is preserved. The evaluator never turns missing evidence into an
    ALLOW decision.
    """
    local = evaluate_local_controls(state)

    if any(item.decision is Decision.DENY for item in local):
        return Evaluation(Decision.DENY, "a local control denied the transition", local)

    if state.internet_reachable is None or state.readable_data is None:
        return Evaluation(
            Decision.INSUFFICIENT_EVIDENCE,
            "cannot establish the cross-system invariant from available evidence",
            local,
        )

    if state.internet_reachable and PROTECTED_DATA in state.readable_data:
        return Evaluation(
            Decision.DENY,
            "internet reachability and protected-data access compose into a forbidden state",
            local,
        )

    return Evaluation(Decision.ALLOW, "declared cross-system invariant holds", local)
