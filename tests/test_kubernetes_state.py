import unittest
from cpal.kubernetes_state import extract_workload_identity


def fixtures():
    pod = {'metadata':{'namespace':'team','name':'worker','uid':'pod-uid','resourceVersion':'11'},
           'spec':{'serviceAccountName':'worker-sa'}}
    account = {'metadata':{'namespace':'team','name':'worker-sa','uid':'sa-uid','resourceVersion':'14'}}
    return pod, account


class WorkloadIdentityTests(unittest.TestCase):
    def test_valid_structure_remains_unauthenticated(self):
        pod, account = fixtures()
        observed = extract_workload_identity(pod, account)
        self.assertEqual(observed.service_account_name, 'worker-sa')
        self.assertFalse(observed.authenticated)

    def test_cross_namespace_mismatch_rejected(self):
        pod, account = fixtures()
        account['metadata']['namespace'] = 'other'
        with self.assertRaises(ValueError):
            extract_workload_identity(pod, account)

    def test_service_account_name_mismatch_rejected(self):
        pod, account = fixtures()
        account['metadata']['name'] = 'other'
        with self.assertRaises(ValueError):
            extract_workload_identity(pod, account)

    def test_missing_resource_version_rejected(self):
        pod, account = fixtures()
        del pod['metadata']['resourceVersion']
        with self.assertRaises(ValueError):
            extract_workload_identity(pod, account)

if __name__ == '__main__':
    unittest.main()
