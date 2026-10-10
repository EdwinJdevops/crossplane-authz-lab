"""State freshness checks for observed probe reports.

This module is NOT an authenticated evidence collector. A caller-supplied
snapshot, run ID or timestamp cannot prove authenticity. Successful matching
only establishes structural consistency, never authorization to execute.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class FreshnessVerdict(str, Enum):
    MATCHED_UNAUTHENTICATED = 'MATCHED_UNAUTHENTICATED'
    INSUFFICIENT_EVIDENCE = 'INSUFFICIENT_EVIDENCE'


@dataclass(frozen=True)
class ProbeBinding:
    execution_id: str
    state_digest: str
    policy_digest: str


def check_probe_freshness(report: Mapping[str, object], expected: ProbeBinding) -> FreshnessVerdict:
    """Check equality only; caller must authenticate evidence independently."""
    values = (expected.execution_id, expected.state_digest, expected.policy_digest)
    if any(not isinstance(value, str) or not value.strip() for value in values):
        return FreshnessVerdict.INSUFFICIENT_EVIDENCE
    if any(report.get(field) != getattr(expected, field) for field in ('execution_id', 'state_digest', 'policy_digest')):
        return FreshnessVerdict.INSUFFICIENT_EVIDENCE
    return FreshnessVerdict.MATCHED_UNAUTHENTICATED
