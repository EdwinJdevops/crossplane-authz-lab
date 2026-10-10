import unittest
from cpal.kubernetes_collector import collect_pod_service_account

class Core:
    def __init__(self, wrong=False): self.wrong=wrong
    def read_namespaced_pod(self, **kwargs):
        return {'metadata': {'name':'other' if self.wrong else 'worker', 'namespace':'team', 'uid':'pod-1', 'resource_version':'10'},
                'spec': {'service_account_name':'worker-sa'}}
    def read_namespaced_service_account(self, **kwargs):
        return {'metadata': {'name':'worker-sa', 'namespace':'team', 'uid':'sa-1', 'resource_version':'11'}}

class CollectorTests(unittest.TestCase):
    def test_reads_matching_identity(self):
        observed = collect_pod_service_account(Core(), namespace='team', pod_name='worker')
        self.assertEqual(observed.pod_uid, 'pod-1')
        self.assertEqual(observed.service_account_uid, 'sa-1')
        self.assertFalse(observed.authenticated)
    def test_rejects_unexpected_pod(self):
        with self.assertRaises(ValueError):
            collect_pod_service_account(Core(wrong=True), namespace='team', pod_name='worker')
    def test_rejects_empty_request(self):
        with self.assertRaises(ValueError):
            collect_pod_service_account(Core(), namespace='', pod_name='worker')

if __name__ == '__main__': unittest.main()
