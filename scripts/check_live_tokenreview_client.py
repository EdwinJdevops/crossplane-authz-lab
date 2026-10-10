"""Live kind TokenReview client test. Requires disposable cluster and kubeconfig.

The CI runner obtains a short-lived collector token and verifier token.
Tokens are never printed.
"""

import os
import subprocess
import tempfile

from cpal.tokenreview_client import authenticate_collector


def kubectl(*args):
    return subprocess.check_output(['kubectl', *args], text=True).strip()


def main():
    namespace = 'cpal-experiment'
    collector = 'cpal-collector'
    verifier = 'cpal-token-verifier'
    audience = 'cpal-collector-verification'
    candidate = kubectl('-n', namespace, 'create', 'token', collector, '--audience=' + audience, '--duration=10m')
    verifier_token = kubectl('-n', namespace, 'create', 'token', verifier, '--duration=10m')
    uid = kubectl('-n', namespace, 'get', 'serviceaccount', collector, '-o', 'jsonpath={.metadata.uid}')
    ca_data = kubectl('-n', namespace, 'get', 'configmap', 'kube-root-ca.crt', '-o', 'jsonpath={.data.ca\\.crt}')
    # CI kind API endpoint is supplied via kubeconfig, not caller-controlled report data.
    endpoint = kubectl('config', 'view', '--minify', '-o', 'jsonpath={.clusters[0].cluster.server}')
    with tempfile.NamedTemporaryFile(mode='w', suffix='.crt') as f:
        f.write(ca_data)
        f.flush()
        kwargs = dict(api_url=endpoint, cluster_ca=f.name, verifier_token=verifier_token, candidate_token=candidate, expected_username=f'system:serviceaccount:{namespace}:{collector}', expected_uid=uid, audience=audience)
        good = authenticate_collector(**kwargs)
        if not good.authenticated:
            raise RuntimeError('Expected authenticated collector, got ' + good.reason)
        print('Live TokenReview client: collector identity verified', flush=True)
        wrong = authenticate_collector(**{**kwargs, 'expected_uid': 'wrong-uid'})
        if wrong.authenticated or wrong.reason != 'IDENTITY_MISMATCH':
            raise RuntimeError('Wrong UID not rejected: ' + wrong.reason)
        print('Live TokenReview client: wrong UID rejected', flush=True)
        wrong_audience = authenticate_collector(**{**kwargs, 'audience': 'wrong-audience'})
        if wrong_audience.authenticated:
            raise RuntimeError('Wrong audience accepted')
        print('Live TokenReview client: wrong audience rejected', flush=True)
        invalid = authenticate_collector(**{**kwargs, 'candidate_token': 'invalid'})
        if invalid.authenticated:
            raise RuntimeError('Invalid token accepted')
        print('Live TokenReview client: invalid token rejected', flush=True)


if __name__ == '__main__':
    main()
