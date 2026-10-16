import json
import unittest
from unittest.mock import patch

from cpal.independent_pod_observation import verify_pod_observation


class FakeResponse:
    status = 200
    def __init__(self, data):
        self.data = data
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size=-1):
        return self.data[:size]


class MalformedObservationTests(unittest.TestCase):
    def setUp(self):
        self.observation = b'{"apiVersion":"cpal.dev/v1alpha1","observation":{"kind":"Pod","namespace":"ns","name":"pod","uid":"u","resourceVersion":"1"},"execution_id":"e"}'
        self.kwargs = dict(report=self.observation, api_url='https://kubernetes.default.svc', cluster_ca='ca', verifier_token='token', namespace='ns', pod_name='pod')

    def test_duplicate_report_key_rejected(self):
        bad = self.observation.replace(b'"execution_id":"e"', b'"execution_id":"e","execution_id":"other"')
        self.assertFalse(verify_pod_observation(**{**self.kwargs, 'report':bad}))

    def test_nan_report_rejected(self):
        bad = self.observation.replace(b'"execution_id":"e"', b'"execution_id":NaN')
        self.assertFalse(verify_pod_observation(**{**self.kwargs, 'report':bad}))

    @patch('cpal.independent_pod_observation.ssl.create_default_context')
    @patch('cpal.independent_pod_observation.urllib.request.build_opener')
    def test_oversized_api_response_rejected(self, opener, context):
        opener.return_value.open.return_value = FakeResponse(b' ' * 65537)
        self.assertFalse(verify_pod_observation(**self.kwargs))


if __name__ == '__main__':
    unittest.main()
