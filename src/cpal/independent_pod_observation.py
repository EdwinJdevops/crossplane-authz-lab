"""Verifier-side Kubernetes Pod identity check using verifier-owned credentials.

This proves the current API view of one scoped Pod's identity, not the
integrity of arbitrary collector reports or an AWS authorization invariant.
"""
import json
import re
import ssl
import urllib.error
import urllib.request


_NAME = re.compile(r'[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\Z')


def verify_pod_observation(*, report: bytes, api_url: str, cluster_ca: str, verifier_token: str, namespace: str, pod_name: str, timeout: int = 5) -> bool:
    if not isinstance(report, bytes) or len(report) > 65536:
        return False
    if not isinstance(api_url, str) or not api_url.startswith('https://'):
        return False
    if not all(isinstance(x, str) and 0 < len(x) <= 63 and _NAME.fullmatch(x) for x in (namespace, pod_name)):
        return False
    if not cluster_ca or not verifier_token:
        return False
    try:
        report_obj = json.loads(report)
        if not isinstance(report_obj, dict) or set(report_obj) != {'apiVersion', 'observation', 'execution_id'} or report_obj['apiVersion'] != 'cpal.dev/v1alpha1':
            return False
        observation = report_obj['observation']
        if not isinstance(observation, dict) or set(observation) != {'kind', 'namespace', 'name', 'uid', 'resourceVersion'}:
            return False
        if observation['kind'] != 'Pod' or observation['namespace'] != namespace or observation['name'] != pod_name:
            return False
        if not all(isinstance(observation.get(key), str) and observation[key] for key in ('uid', 'resourceVersion')):
            return False
        context = ssl.create_default_context(cafile=cluster_ca)
        request = urllib.request.Request(api_url.rstrip('/') + f'/api/v1/namespaces/{namespace}/pods/{pod_name}', headers={'Authorization': 'Bearer ' + verifier_token, 'Accept': 'application/json'}, method='GET')
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
            if response.status != 200:
                return False
            live = json.load(response)
        metadata = live.get('metadata') if isinstance(live, dict) and live.get('kind') == 'Pod' else None
        return isinstance(metadata, dict) and metadata.get('namespace') == namespace and metadata.get('name') == pod_name and metadata.get('uid') == observation['uid'] and metadata.get('resourceVersion') == observation['resourceVersion']
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError):
        return False
