from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .live_probe_binding import ExpectedProbe, ProbeVerdict, interpret_probe


@dataclass(frozen=True)
class ProbeProvenance:
    """Evidence transport attestation from a trusted collector, not user JSON.

    `authenticated` must only be set by an out-of-band verified transport.
    This module does not implement such a transport or validate signatures.
    """
    authenticated: bool
    collector_identity: str
    execution_id: str


def evaluate_trusted_probe(
    report: Mapping[str, object], expected: ExpectedProbe,
    provenance: ProbeProvenance | None,
) -> ProbeVerdict:
    """Fail closed until a separate trusted collector authenticates the report."""
    if provenance is None or not provenance.authenticated:
        return ProbeVerdict.INSUFFICIENT_EVIDENCE
    if not provenance.collector_identity.strip() or not provenance.execution_id.strip():
        return ProbeVerdict.INSUFFICIENT_EVIDENCE
    # A caller-constructed provenance object is not a security boundary.
    # Only invoke from a trusted collector after transport authentication.
    return interpret_probe(report, expected)
