"""Check a pair of captured live probe reports; this does not authenticate their origin."""
import argparse
import json
from pathlib import Path
from cpal.live_probe_binding import ExpectedProbe, ProbeVerdict, interpret_probe


def validate_pair(allowed, denied, expected_role, bucket, allowed_key, denied_key, region):
    positive = interpret_probe(allowed, ExpectedProbe(expected_role, bucket, allowed_key, region))
    negative = interpret_probe(denied, ExpectedProbe(expected_role, bucket, denied_key, region))
    return positive == ProbeVerdict.VERIFIED_READ and negative == ProbeVerdict.VERIFIED_DENIAL


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--positive', type=Path, required=True)
    p.add_argument('--negative', type=Path, required=True)
    p.add_argument('--role-arn', required=True)
    p.add_argument('--bucket', required=True)
    p.add_argument('--allowed-key', required=True)
    p.add_argument('--denied-key', required=True)
    p.add_argument('--region', default='us-east-1')
    args = p.parse_args()
    ok = validate_pair(json.loads(args.positive.read_text()), json.loads(args.negative.read_text()),
                       args.role_arn, args.bucket, args.allowed_key, args.denied_key, args.region)
    print('PAIR_MATCHES_EXPECTED_OUTCOMES' if ok else 'PAIR_INCONCLUSIVE_OR_MISMATCHED')
    raise SystemExit(0 if ok else 1)
