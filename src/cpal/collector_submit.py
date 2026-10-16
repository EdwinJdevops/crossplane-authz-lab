"""Experimental in-pod collector: read scoped Pod and submit over verified TLS.

Requires separately provisioned trusted verifier CA and scoped projected token.
Does not establish independent provenance or enable authorization.
"""
import base64
import hashlib
import json
import ssl
import re
import urllib.request


def collect_and_submit(*, kubernetes_url, kubernetes_ca, token_path, kubernetes_token_path, namespace, pod_name, verifier_url, verifier_ca, collector_service_account, timeout=10):
    if not kubernetes_url.startswith('https://') or not verifier_url.startswith('https://'):
        raise ValueError('TLS required for both API endpoints')
    name_pattern = re.compile(r'[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\Z')
    if not all(isinstance(value, str) and len(value) <= 63 and name_pattern.fullmatch(value) for value in (namespace, pod_name, collector_service_account)):
        raise ValueError('invalid scoped resource')
    with open(token_path, encoding='utf-8') as file:
        token = file.read().strip()
    if not token:
        raise ValueError('missing projected token')
    with open(kubernetes_token_path, encoding='utf-8') as file:
        kubernetes_token = file.read().strip()
    if not kubernetes_token:
        raise ValueError('missing Kubernetes API token')
    kube_context = ssl.create_default_context(cafile=kubernetes_ca)
    verifier_context = ssl.create_default_context(cafile=verifier_ca)

    def request(url, context, bearer, method='GET', data=None):
        headers = {'Authorization': 'Bearer ' + bearer, 'Accept': 'application/json'}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(url, headers=headers, data=data, method=method)
        with urllib.request.urlopen(req, context=context, timeout=timeout) as response:
            return json.load(response)

    challenge = request(verifier_url.rstrip('/') + '/challenge', verifier_context, token, 'POST', b'')
    if not isinstance(challenge, dict) or challenge.get('accepted') is not True or not all(isinstance(challenge.get(k), str) and challenge[k] for k in ('nonce', 'execution_id')):
        raise ValueError('verifier challenge rejected')
    pod = request(kubernetes_url.rstrip('/') + f'/api/v1/namespaces/{namespace}/pods/{pod_name}', kube_context, kubernetes_token)
    if not isinstance(pod, dict) or pod.get('kind') != 'Pod' or not isinstance(pod.get('metadata'), dict) or pod['metadata'].get('name') != pod_name or pod['metadata'].get('namespace') != namespace:
        raise ValueError('unexpected Kubernetes observation')
    if not all(isinstance(pod['metadata'].get(k), str) and pod['metadata'][k] for k in ('uid', 'resourceVersion')):
        raise ValueError('missing Kubernetes observation identity')
    report = json.dumps({'apiVersion': 'cpal.dev/v1alpha1', 'observation': {'kind': 'Pod', 'namespace': namespace, 'name': pod_name, 'uid': pod['metadata'].get('uid'), 'resourceVersion': pod['metadata'].get('resourceVersion')}, 'execution_id': challenge['execution_id']}, sort_keys=True, separators=(',', ':')).encode()
    if len(report) > 65536:
        raise ValueError('report too large')
    principal = f'system:serviceaccount:{namespace}:{collector_service_account}'
    envelope = {'principal': principal, 'nonce': challenge['nonce'], 'execution_id': challenge['execution_id'], 'report_sha256': hashlib.sha256(report).hexdigest()}
    submission = json.dumps({'report_b64': base64.b64encode(report).decode('ascii'), 'envelope': envelope}, separators=(',', ':')).encode()
    result = request(verifier_url.rstrip('/') + '/reports', verifier_context, token, 'POST', submission)
    if result.get('accepted') is not True:
        raise ValueError('verifier rejected submitted report')
    return result
