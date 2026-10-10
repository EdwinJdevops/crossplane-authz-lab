"""Probe actual S3 authorization using a role session, never the caller's admin credentials.

Usage (after creating a private disposable bucket/object and a restricted role):
  python scripts/verify_effective_s3_role.py --role-arn ARN --bucket BUCKET --key KEY

The caller must be authorized to sts:AssumeRole. No credentials are printed.
This script is read-only: GetObject and DeleteObject authorization is tested
via a denied HeadObject? No: DeleteObject is NOT attempted because destructive.
A missing GetObject success is reported as inconclusive if the error is not
AccessDenied; IAM simulation is not substituted for a live request.
"""
import argparse
import json

import boto3
from botocore.exceptions import ClientError


def probe(role_arn: str, bucket: str, key: str, region: str) -> dict:
    sts = boto3.client('sts', region_name=region)
    assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName='cpal-effective-access-probe', DurationSeconds=900)
    credentials = assumed['Credentials']
    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region,
    )
    identity = session.client('sts').get_caller_identity()['Arn']
    s3 = session.client('s3')
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        response['Body'].close()
        outcome = 'GET_OBJECT_SUCCEEDED'
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code', 'UNKNOWN')
        outcome = 'GET_OBJECT_ACCESS_DENIED' if code in {'AccessDenied', '403'} else 'GET_OBJECT_INCONCLUSIVE'
    return {'assumed_role_session_arn': identity, 'bucket': bucket, 'key': key, 'get_object_outcome': outcome}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role-arn', required=True)
    parser.add_argument('--bucket', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--region', default='us-east-1')
    args = parser.parse_args()
    print(json.dumps(probe(args.role_arn, args.bucket, args.key, args.region), indent=2))
