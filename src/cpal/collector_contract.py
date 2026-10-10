from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .live_probe_binding import ExpectedProbe, ProbeVerdict, interpret_probe


@dataclass(frozen=True)
class CollectorExpectation:
    execution_id: str
    collector_identity: str
    probe: ExpectedProbe


def validate_collector_report(report: Mapping[str, object], expected: CollectorExpectation) -> ProbeVerdict:
    """Validate report fields only; NOT cryptographic or transport authentication.

    Reports from this function remain INSUFFICIENT_EVIDENCE until a trusted
    collector independently binds the result to an authenticated execution.
    A matching report is not proof that any AWS call took place.
    """
    if not expected.execution_id or not expected.collector_identity:
        return ProbeVerdict.INSUFFICIENT_EVIDENCE
    if report.get('execution_id') != expected.execution_id:
        return ProbeVerdict.INSUFFICIENT_EVIDENCE
    if report.get('collector_identity') != expected.collector_identity:
        return ProbeVerdict.INSUFFICIENT_EVIDENCE
    if interpret_probe(report, expected.probe) == ProbeVerdict.INSUFFICIENT_EVIDENCE:
        return ProbeVerdict.INSUFFICIENT_EVIDENCE
    return ProbeVerdict.INSUFFICIENT_EVIDENCE
