import unittest
from cpal.access_requirements import RequirementStatus as S, s3_get_object_contract

class AccessRequirementTests(unittest.TestCase):
    def test_all_authoritative_components_satisfied(self):
        r=s3_get_object_contract(identity=S.SATISFIED,boundary=S.SATISFIED,scp=S.SATISFIED,bucket_policy=S.SATISFIED,rcp=S.SATISFIED,endpoint_policy=S.SATISFIED)
        self.assertEqual(r.status,S.SATISFIED)

    def test_simulator_gap_keeps_claim_unknown(self):
        r=s3_get_object_contract(identity=S.SATISFIED,boundary=S.SATISFIED,scp=S.SATISFIED,bucket_policy=S.UNKNOWN,rcp=S.UNKNOWN,endpoint_policy=S.UNKNOWN)
        self.assertEqual(r.status,S.UNKNOWN)
        self.assertIn("bucket-policy",r.reason)

    def test_any_required_deny_blocks_access(self):
        r=s3_get_object_contract(identity=S.SATISFIED,boundary=S.SATISFIED,scp=S.DENIED,bucket_policy=S.SATISFIED,rcp=S.SATISFIED,endpoint_policy=S.SATISFIED)
        self.assertEqual(r.status,S.DENIED)

    def test_kms_is_required_when_object_uses_kms(self):
        r=s3_get_object_contract(identity=S.SATISFIED,boundary=S.SATISFIED,scp=S.SATISFIED,bucket_policy=S.SATISFIED,rcp=S.SATISFIED,endpoint_policy=S.SATISFIED,kms=S.UNKNOWN)
        self.assertEqual(r.status,S.UNKNOWN)
        self.assertIn("kms-decrypt",r.reason)

if __name__=="__main__": unittest.main()
