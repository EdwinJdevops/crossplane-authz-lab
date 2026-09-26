from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping


def digest_state(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    subject: str
    state_digest: str

    def validate(self) -> None:
        if not self.evidence_id or not self.subject or not self.state_digest:
            raise ValueError("evidence id, subject, and digest are required")


@dataclass(frozen=True)
class BoundAuthorization:
    authorization_id: str
    operation_digest: str
    evidence: tuple[Evidence, ...]

    def validate(self) -> None:
        if not self.authorization_id or not self.operation_digest:
            raise ValueError("authorization id and operation digest are required")
        if not self.evidence:
            raise ValueError("authorization must bind at least one evidence item")
        subjects: set[str] = set()
        for item in self.evidence:
            item.validate()
            if item.subject in subjects:
                raise ValueError(f"duplicate evidence subject: {item.subject}")
            subjects.add(item.subject)


def current_digests(state: Mapping[str, str]) -> dict[str, str]:
    return {subject: digest_state(value) for subject, value in state.items()}
