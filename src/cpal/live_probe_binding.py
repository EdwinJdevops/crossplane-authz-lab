from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class ProbeVerdict(str, Enum):
    VERIFIED_READ = 'VERIFIED_READ'
    VERIFIED_DENIAL = 'VERIFIED_DENIAL'
    INSUFFICIENT_EVIDENCE = 'INSUFFICIENT_EVIDENCE'


@dataclass(frozen=True)
class ExpectedProbe:
    role_arn: str
    bucket: str
    key: str
    region: str


def interpret_probe(result: Mapping[str, object], expected: ExpectedProbe) -> ProbeVerdict:
    """Interpret a probe report; does NOT authenticate its provenance.

    Only accept reports delivered through a trusted execution channel. An
    arbitrary JSON document cannot establish that an AWS API call occurred.
    """
    session_arn = result.get('assumed_role_session_arn')
    if not isinstance(session_arn, str) or ':assumed-role/' not in session_arn:
        return ProbeVerdict.INSUFFICIENT_EVIDENCE
    try:
        account, role_name = expected.role_arn.split(':role/', 1)
        account_id = account.split(':')[-1]
    except ValueError:
        return ProbeVerdict.INSUFFICIENT_EVIDENCE
    if not account_id.isdigit() or not role_name or '/' in role_name:
        return ProbeVerdict.INSUFFICIENT_EVIDENCE
    prefix = f'arn:aws:sts::{account_id}:assumed-role/{role_name}/'
    if not session_arn.startswith(prefix) or len(session_arn) <= len(prefix):
        return ProbeVerdict.INSUFFICIENT_EVIDENCE
    if any(result.get(field) != getattr(expected, field) for field in ('bucket', 'key', 'region')):
        return ProbeVerdict.INSUFFICIENT_EVIDENCE
    outcome = result.get('get_object_outcome')
    error = result.get('aws_error_code')
    if outcome == 'GET_OBJECT_SUCCEEDED' and error is None:
        return ProbeVerdict.VERIFIED_READ
    if outcome == 'GET_OBJECT_ACCESS_DENIED' and error in ('AccessDenied', '403'):
        return ProbeVerdict.VERIFIED_DENIAL
    return ProbeVerdict.INSUFFICIENT_EVIDENCE
