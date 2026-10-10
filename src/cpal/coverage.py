from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .evidence import BoundAuthorization
from .freshness import FreshnessResult, evaluate_authorization_freshness
from .model import Decision


@dataclass(frozen=True)
class DependencyCoverage:
    """A caller-supplied coverage claim, NOT independently proven completeness.

    Unknown dependencies must be declared explicitly. The caller must not
    invent required subjects merely to obtain ALLOW.
    """

    required_subjects: frozenset[str]
    unknown_dependencies: tuple[str, ...] = ()
    complete: bool = False


def evaluate_with_coverage(
    authorization: BoundAuthorization,
    current_state_digests: Mapping[str, str],
    operation_digest: str,
    coverage: DependencyCoverage,
) -> FreshnessResult:
    authorization.validate()
    if not coverage.complete or coverage.unknown_dependencies:
        return FreshnessResult(
            Decision.INSUFFICIENT_EVIDENCE,
            'dependency closure has not been established',
            missing_subjects=tuple(sorted(coverage.unknown_dependencies)),
        )
    if not coverage.required_subjects:
        return FreshnessResult(Decision.INSUFFICIENT_EVIDENCE, 'required dependency set is empty')
    bound = {e.subject for e in authorization.evidence}
    missing = coverage.required_subjects - bound
    if missing:
        return FreshnessResult(
            Decision.INSUFFICIENT_EVIDENCE,
            'required dependencies are not bound to the authorization',
            missing_subjects=tuple(sorted(missing)),
        )
    return evaluate_authorization_freshness(authorization, current_state_digests, operation_digest)
