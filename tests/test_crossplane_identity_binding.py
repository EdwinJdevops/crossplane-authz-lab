import dataclasses
import unittest
from cpal.crossplane_identity_binding import ExpectedBinding, VerifiedAWSIdentity, VerifiedKubernetesIdentity, identities_bound


class CrossplaneIdentityBindingTests(unittest.TestCase):
    def setUp(self):
        self.expected = ExpectedBinding('123456789012','arn:aws:sts::123456789012:assumed-role/verifier/session','ns','pod-uid','execution-1')
        self.aws = VerifiedAWSIdentity(self.expected.aws_account,self.expected.aws_arn,self.expected.execution_id,True)
        self.kube = VerifiedKubernetesIdentity(self.expected.namespace,self.expected.pod_uid,self.expected.execution_id,True)

    def test_positive_binding(self):
        self.assertTrue(identities_bound(self.aws,self.kube,self.expected))

    def test_independent_source_required(self):
        self.assertFalse(identities_bound(dataclasses.replace(self.aws,verified_by_sts=False),self.kube,self.expected))
        self.assertFalse(identities_bound(self.aws,dataclasses.replace(self.kube,verified_by_api=False),self.expected))

    def test_adversarial_identity_mutations(self):
        for field,value in [('account','000000000000'),('arn','arn:aws:iam::123456789012:user/attacker'),('execution_id','stale-execution')]:
            with self.subTest(side='aws',field=field):
                self.assertFalse(identities_bound(dataclasses.replace(self.aws,**{field:value}),self.kube,self.expected))
        for field,value in [('namespace','other'),('pod_uid','recreated-pod'),('execution_id','different-execution')]:
            with self.subTest(side='kubernetes',field=field):
                self.assertFalse(identities_bound(self.aws,dataclasses.replace(self.kube,**{field:value}),self.expected))

    def test_missing_evidence_denied(self):
        self.assertFalse(identities_bound(None,self.kube,self.expected))
        self.assertFalse(identities_bound(self.aws,None,self.expected))
        self.assertFalse(identities_bound(self.aws,self.kube,None))

    def test_empty_binding_denied(self):
        self.assertFalse(identities_bound(self.aws,self.kube,dataclasses.replace(self.expected,execution_id='')))


if __name__ == '__main__':
    unittest.main()
