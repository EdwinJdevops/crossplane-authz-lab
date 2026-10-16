import base64
import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from cpal.collector_submit import collect_and_submit


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, *args):
        return json.dumps(self.payload).encode()


class CollectorSubmitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.token_path = os.path.join(self.temp.name, 'token')
        with open(self.token_path, 'w') as f:
            f.write('projected-token')
        self.args = dict(kubernetes_url='https://kubernetes.default.svc', kubernetes_ca='kube-ca', token_path=self.token_path, kubernetes_token_path=self.token_path, namespace='cpal-experiment', pod_name='cpal-target', verifier_url='https://verifier.cpal-experiment.svc', verifier_ca='verifier-ca', collector_service_account='cpal-collector')

    def test_rejects_plaintext_transport(self):
        with self.assertRaises(ValueError):
            collect_and_submit(**{**self.args, 'verifier_url': 'http://verifier'})

    def test_rejects_missing_token(self):
        with open(self.token_path, 'w') as f:
            f.write('')
        with patch('cpal.collector_submit.ssl.create_default_context'):
            with self.assertRaises(ValueError):
                collect_and_submit(**self.args)

    def test_real_observation_bound_to_verifier_challenge(self):
        requests = []
        challenge = {'accepted': True, 'nonce': 'nonce-from-verifier', 'execution_id': 'execution-from-verifier'}
        pod = {'kind': 'Pod', 'metadata': {'name': 'cpal-target', 'namespace': 'cpal-experiment', 'uid': 'real-uid', 'resourceVersion': '42'}}
        def fake_urlopen(request, *, timeout):
            requests.append(request)
            if request.full_url.endswith('/challenge'):
                return FakeResponse(challenge)
            if request.full_url.endswith('/pods/cpal-target'):
                return FakeResponse(pod)
            if request.full_url.endswith('/reports'):
                return FakeResponse({'accepted': True, 'reason': 'REPORT_ACCEPTED'})
            raise AssertionError(request.full_url)
        with patch('cpal.collector_submit.ssl.create_default_context', side_effect=lambda cafile: cafile), patch('cpal.collector_submit.urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = fake_urlopen
            result = collect_and_submit(**self.args)
        self.assertTrue(result['accepted'])
        self.assertEqual(len(requests), 3)
        self.assertTrue(all(r.get_header('Authorization') == 'Bearer projected-token' for r in requests))
        self.assertEqual(requests[0].data, b'')
        submission = json.loads(requests[2].data)
        report = base64.b64decode(submission['report_b64'])
        parsed = json.loads(report)
        self.assertEqual(parsed['observation']['uid'], 'real-uid')
        self.assertEqual(parsed['execution_id'], 'execution-from-verifier')
        self.assertEqual(submission['envelope']['nonce'], 'nonce-from-verifier')
        self.assertEqual(submission['envelope']['report_sha256'], hashlib.sha256(report).hexdigest())

    def test_rejects_wrong_pod_identity(self):
        def fake_urlopen(request, *, timeout):
            if request.full_url.endswith('/challenge'):
                return FakeResponse({'accepted': True, 'nonce': 'nonce', 'execution_id': 'execution'})
            return FakeResponse({'kind': 'Pod', 'metadata': {'name': 'other', 'namespace': 'cpal-experiment'}})
        with patch('cpal.collector_submit.ssl.create_default_context', return_value=object()), patch('cpal.collector_submit.urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = fake_urlopen
            with self.assertRaises(ValueError):
                collect_and_submit(**self.args)


if __name__ == '__main__':
    unittest.main()
