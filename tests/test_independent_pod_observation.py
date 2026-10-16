import json
import unittest
from unittest.mock import patch

from cpal.independent_pod_observation import verify_pod_observation


class Response:
    status = 200
    def __init__(self, data):
        self.data = data
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self, *args):
        return json.dumps(self.data).encode()


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.report = json.dumps({'apiVersion':'cpal.dev/v1alpha1','observation':{'kind':'Pod','namespace':'cpal-experiment','name':'cpal-target','uid':'uid-1','resourceVersion':'100'},'execution_id':'exec'}).encode()
        self.live = {'kind':'Pod','metadata':{'namespace':'cpal-experiment','name':'cpal-target','uid':'uid-1','resourceVersion':'100'}}
        self.kwargs = dict(report=self.report, api_url='https://kubernetes.default.svc', cluster_ca='ca', verifier_token='token', namespace='cpal-experiment', pod_name='cpal-target')

    @patch('cpal.independent_pod_observation.ssl.create_default_context')
    @patch('cpal.independent_pod_observation.urllib.request.build_opener')
    def test_matching_pod(self, fetch, context):
        fetch.return_value.open.return_value = Response(self.live)
        self.assertTrue(verify_pod_observation(**self.kwargs))

    @patch('cpal.independent_pod_observation.ssl.create_default_context')
    @patch('cpal.independent_pod_observation.urllib.request.build_opener')
    def test_forged_uid_rejected(self, fetch, context):
        fetch.return_value.open.return_value = Response({**self.live, 'metadata': {**self.live['metadata'], 'uid':'attacker'}})
        self.assertFalse(verify_pod_observation(**self.kwargs))

    @patch('cpal.independent_pod_observation.ssl.create_default_context')
    @patch('cpal.independent_pod_observation.urllib.request.build_opener')
    def test_stale_version_rejected(self, fetch, context):
        fetch.return_value.open.return_value = Response({**self.live, 'metadata': {**self.live['metadata'], 'resourceVersion':'101'}})
        self.assertFalse(verify_pod_observation(**self.kwargs))

    @patch('cpal.independent_pod_observation.ssl.create_default_context')
    @patch('cpal.independent_pod_observation.urllib.request.build_opener')
    def test_api_failure_rejected(self, fetch, context):
        fetch.return_value.open.side_effect = OSError('API unavailable')
        self.assertFalse(verify_pod_observation(**self.kwargs))

    def test_wrong_target_rejected_before_network(self):
        self.assertFalse(verify_pod_observation(**{**self.kwargs,'pod_name':'other'}))


if __name__ == '__main__':
    unittest.main()
