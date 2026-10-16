"""Disposable kind TLS verifier; all trust and credential paths are mandatory."""
import os

from cpal.challenge_store import ChallengeStore
from cpal.report_tls import make_tls_server


def required(name):
    value = os.environ.get(name)
    if not value:
        raise ValueError('missing required configuration: ' + name)
    return value


def main():
    namespace = required('CPAL_NAMESPACE')
    service_account = required('CPAL_COLLECTOR_SERVICE_ACCOUNT')
    verifier_token_path = required('CPAL_VERIFIER_TOKEN_PATH')
    server = make_tls_server(host='0.0.0.0', port=8443, certfile=required('CPAL_TLS_CERT'), keyfile=required('CPAL_TLS_KEY'), api_url=required('CPAL_KUBERNETES_URL'), cluster_ca=required('CPAL_KUBERNETES_CA'), verifier_token='', verifier_token_path=verifier_token_path, expected_username=f'system:serviceaccount:{namespace}:{service_account}', expected_uid=required('CPAL_COLLECTOR_UID'), audience='cpal-collector-verification', challenge_store=ChallengeStore(required('CPAL_CHALLENGE_DB')))
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
