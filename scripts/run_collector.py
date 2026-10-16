"""Experimental Kubernetes collector entrypoint; requires verified TLS on both connections."""
import os
from cpal.collector_submit import collect_and_submit


def required(name):
    value = os.environ.get(name)
    if not value:
        raise ValueError(f'missing required configuration: {name}')
    return value


def main():
    result = collect_and_submit(
        kubernetes_url=required('CPAL_KUBERNETES_URL'),
        kubernetes_ca=required('CPAL_KUBERNETES_CA'),
        token_path=required('CPAL_COLLECTOR_TOKEN_PATH'),
        kubernetes_token_path=required('CPAL_KUBERNETES_TOKEN_PATH'),
        namespace=required('CPAL_NAMESPACE'),
        pod_name=required('CPAL_TARGET_POD'),
        verifier_url=required('CPAL_VERIFIER_URL'),
        verifier_ca=required('CPAL_VERIFIER_CA'),
        collector_service_account=required('CPAL_COLLECTOR_SERVICE_ACCOUNT'),
    )
    if not result.get('accepted'):
        raise RuntimeError('verifier rejected collector report')
    print('Collector report accepted by verifier')


if __name__ == '__main__':
    main()
