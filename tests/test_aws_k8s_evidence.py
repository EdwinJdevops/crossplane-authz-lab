import unittest
from scripts.validate_aws_k8s_evidence import REQUIRED, consistent


class CrossPlaneConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.expected = dict(execution_id='run-1', aws_principal_arn='arn:aws:iam::123456789012:role/verifier', aws_resource_arn='arn:aws:s3:::test', kubernetes_pod_uid='uid-1', kubernetes_namespace='ns', policy_digest='sha256:abcd')
    def test_matching_bindings(self):
        self.assertTrue(consistent(dict(self.expected), dict(self.expected), self.expected))
    def test_mismatches_rejected(self):
        for key in REQUIRED:
            for side in ('aws', 'kubernetes'):
                with self.subTest(key=key, side=side):
                    aws, kube = dict(self.expected), dict(self.expected)
                    (aws if side == 'aws' else kube)[key] = 'forged'
                    self.assertFalse(consistent(aws, kube, self.expected))
    def test_missing_expected_binding_rejected(self):
        expected = dict(self.expected)
        expected.pop('policy_digest')
        self.assertFalse(consistent(dict(self.expected), dict(self.expected), expected))
    def test_untrusted_values_rejected(self):
        self.assertFalse(consistent(None, dict(self.expected), self.expected))


if __name__ == '__main__':
    unittest.main()
