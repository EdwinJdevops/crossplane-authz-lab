from __future__ import annotations

from dataclasses import dataclass

from .model import Decision, WorkloadState


@dataclass(frozen=True)
class LocalDecision:
    plane: str
    decision: Decision
    reason: str


def network_policy(state: WorkloadState) -> LocalDecision:
    """Local network-plane policy.

    Internet exposure is permitted. The network plane deliberately has no
    knowledge of data authorization.
    """
    if state.internet_reachable is None:
        return LocalDecision("network", Decision.INSUFFICIENT_EVIDENCE, "network reachability unknown")
    return LocalDecision("network", Decision.ALLOW, "network state satisfies local policy")


def data_policy(state: WorkloadState) -> LocalDecision:
    """Local data/IAM-plane policy.

    Reading the protected dataset is permitted for this workload identity.
    The data plane deliberately has no knowledge of network exposure.
    """
    if state.readable_data is None:
        return LocalDecision("data", Decision.INSUFFICIENT_EVIDENCE, "data authorization unknown")
    return LocalDecision("data", Decision.ALLOW, "data authorization satisfies local policy")


def evaluate_local_controls(state: WorkloadState) -> tuple[LocalDecision, LocalDecision]:
    state.validate()
    return network_policy(state), data_policy(state)
