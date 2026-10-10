"""Read-only actual S3 GetObject probe using a temporary assumed-role session.

Run against disposable, non-sensitive objects only. A successful read proves
access for this role session, object, and time; it does not prove Kubernetes
IRSA, network reachability, or cross-system dependency completeness.

For a negative control, test an existing object outside the role's allowed ARN.
No DeleteObject, PutObject, or policy mutation is performed here.
"""
import argparse
import json

import boto3
from botocore.exceptions import ClientError


def classify_get_error(code: str) -> str:
    return 'GET_OBJECT_ACCESS_DENIED' if code in {'AccessDenied', '403'} else 'GET_OBJECT_INCONCLUSIVE'


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
    error_code = None
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        response['Body'].close()
        outcome = 'GET_OBJECT_SUCCEEDED'
    except ClientError as exc:
        error_code = exc.response.get('Error', {}).get('Code', 'UNKNOWN')
        outcome = classify_get_error(error_code)
    return {'assumed_role_session_arn': identity, 'bucket': bucket, 'key': key,
            'region': region, 'get_object_outcome': outcome, 'aws_error_code': error_code}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role-arn', required=True)
    parser.add_argument('--bucket', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--region', default='us-east-1')
    args = parser.parse_args()
    print(json.dumps(probe(args.role_arn, args.bucket, args.key, args.region), indent=2))
