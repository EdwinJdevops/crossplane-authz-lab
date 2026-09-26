from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    BOUNDED_EXECUTION = "BOUNDED_EXECUTION"


@dataclass(frozen=True)
class WorkloadState:
    name: str
    internet_reachable: bool | None
    readable_data: FrozenSet[str] | None

    def validate(self) -> None:
        if not self.name:
            raise ValueError("workload name must be non-empty")
        if self.readable_data is not None and any(not item for item in self.readable_data):
            raise ValueError("data resource names must be non-empty")
