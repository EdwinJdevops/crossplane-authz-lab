import unittest
from cpal.kubernetes_consistency import collect_stable_identity

class FakeCore:
    def __init__(self, mutate=False):
        self.mutate = mutate
        self.reads = 0
    def read_namespaced_pod(self, **kwargs):
        self.reads += 1
        version = '2' if self.mutate and self.reads > 1 else '1'
        return {'metadata':{'namespace':'team','name':'worker','uid':'pod-uid','resource_version':version},
                'spec':{'service_account_name':'worker-sa'}}
    def read_namespaced_service_account(self, **kwargs):
        return {'metadata':{'namespace':'team','name':'worker-sa','uid':'sa-uid','resource_version':'1'}}

class ConsistencyTests(unittest.TestCase):
    def test_stable_identity_is_not_authenticated(self):
        result = collect_stable_identity(FakeCore(), namespace='team', pod_name='worker')
        self.assertFalse(result.authenticated)
        self.assertEqual(result.pod_resource_version, '1')
    def test_changed_pod_version_rejected(self):
        with self.assertRaises(ValueError):
            collect_stable_identity(FakeCore(mutate=True), namespace='team', pod_name='worker')

if __name__ == '__main__':
    unittest.main()
