"""Independent AWS STS caller identity probe, never a standalone allow decision.

Run under the verifier's actual staging IAM role, not a developer IAM user.
Requires explicit expected account and principal ARN; no default trust values.
"""
import argparse
import json
import re


def verify_identity(sts, *, expected_account, expected_arn):
    if not re.fullmatch(r'[0-9]{12}', expected_account) or not expected_arn.startswith('arn:aws:sts::' + expected_account + ':assumed-role/'):
        return False
    response = sts.get_caller_identity()
    return response.get('Account') == expected_account and response.get('Arn') == expected_arn and bool(response.get('UserId'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-account', required=True)
    parser.add_argument('--expected-arn', required=True)
    args = parser.parse_args()
    import boto3
    accepted = verify_identity(boto3.client('sts'), expected_account=args.expected_account, expected_arn=args.expected_arn)
    print(json.dumps({'aws_identity_verified':accepted}))
    if not accepted:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
