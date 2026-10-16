"""Fail-closed release admission. Run from the repository root.

Evidence is deliberately not inferred from unit-test success or self-attestation.
Only independently reviewed artifacts can close release gates.
"""
import json
import os
import sys
from pathlib import Path

REQUIRED = ('observation_integrity', 'durable_multi_replica_state', 'aws_kubernetes_adversarial', 'operational_assurance')


def assess(path):
    try:
        record = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False, ['release evidence missing or invalid']
    if not isinstance(record, dict) or set(record) != set(REQUIRED):
        return False, ['release evidence has missing or unknown gates']
    failures = []
    for name in REQUIRED:
        gate = record[name]
        if not isinstance(gate, dict) or gate.get('approved') is not True or not isinstance(gate.get('reviewer'), str) or not gate['reviewer'].strip() or not isinstance(gate.get('evidence_url'), str) or not gate['evidence_url'].startswith('https://'):
            failures.append(name)
    return not failures, failures


def main():
    path = os.environ.get('CPAL_RELEASE_EVIDENCE', 'release-evidence.json')
    accepted, failures = assess(path)
    print(json.dumps({'production_admission': 'GO' if accepted else 'NO-GO', 'unverified': failures}, sort_keys=True))
    return 0 if accepted else 1


if __name__ == '__main__':
    sys.exit(main())
