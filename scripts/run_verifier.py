"""Staging TLS verifier with explicitly configured trust and credentials."""
import os

from cpal.aws_identity import valid_expected_identity
from cpal.challenge_store import ChallengeStore
from cpal.report_tls import make_tls_server


def make_challenge_store():
    table_name = os.environ.get('CPAL_DYNAMODB_CHALLENGE_TABLE')
    if table_name:
        import boto3
        from cpal.dynamodb_challenge_store import DynamoDBChallengeStore
        return DynamoDBChallengeStore(boto3.resource('dynamodb').Table(table_name))
    if os.environ.get('CPAL_PRODUCTION_MODE') == '1':
        raise ValueError('production requires durable DynamoDB challenge table')
    return ChallengeStore(required('CPAL_CHALLENGE_DB'))
def required(name):
    value = os.environ.get(name)
    if not value:
        raise ValueError('missing required configuration: ' + name)
    return value


def make_aws_config():
    if os.environ.get('CPAL_KIND_FIXTURE') == '1':
        if any(name in os.environ for name in ('CPAL_AWS_ACCOUNT', 'CPAL_AWS_ROLE_ARN', 'CPAL_AWS_REGION')):
            raise ValueError('kind fixture and AWS configuration cannot be combined')
        return {}
    account = required('CPAL_AWS_ACCOUNT')
    arn = required('CPAL_AWS_ROLE_ARN')
    if not valid_expected_identity(account, arn):
        raise ValueError('invalid expected STS assumed-role identity')
    region = required('CPAL_AWS_REGION')
    import boto3
    from botocore.config import Config

    sts = boto3.client('sts', region_name=region, config=Config(
        ignore_configured_endpoint_urls=True,
        connect_timeout=3,
        read_timeout=5,
        retries={'total_max_attempts': 1},
    ))
    return dict(sts=sts, expected_aws_account=account, expected_aws_arn=arn)


def main():
    if os.environ.get('CPAL_PRODUCTION_MODE') == '1':
        raise SystemExit('INDEPENDENT_COLLECTOR_ATTESTATION_REQUIRED')
    namespace = required('CPAL_NAMESPACE')
    service_account = required('CPAL_COLLECTOR_SERVICE_ACCOUNT')
    verifier_token_path = required('CPAL_VERIFIER_TOKEN_PATH')
    server = make_tls_server(
        host=os.environ.get('CPAL_BIND_HOST', '127.0.0.1'), port=8443,
        certfile=required('CPAL_TLS_CERT'), keyfile=required('CPAL_TLS_KEY'),
        api_url=required('CPAL_KUBERNETES_URL'), cluster_ca=required('CPAL_KUBERNETES_CA'),
        verifier_token='', verifier_token_path=verifier_token_path,
        observation_namespace=namespace, observation_pod=required('CPAL_OBSERVATION_POD'),
        expected_username=f'system:serviceaccount:{namespace}:{service_account}',
        expected_uid=required('CPAL_COLLECTOR_UID'), audience='cpal-collector-verification',
        challenge_store=make_challenge_store(), **make_aws_config(),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
