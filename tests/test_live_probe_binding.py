import unittest
from cpal.live_probe_binding import ExpectedProbe, ProbeVerdict, interpret_probe

EXPECTED = ExpectedProbe('arn:aws:iam::111122223333:role/probe', 'fixture-bucket', 'fixture/ok', 'us-east-1')
BASE = {'assumed_role_session_arn':'arn:aws:sts::111122223333:assumed-role/probe/session',
        'bucket':'fixture-bucket', 'key':'fixture/ok', 'region':'us-east-1',
        'get_object_outcome':'GET_OBJECT_SUCCEEDED', 'aws_error_code':None}

class LiveProbeBindingTests(unittest.TestCase):
    def test_matching_read_report(self):
        self.assertEqual(interpret_probe(BASE, EXPECTED), ProbeVerdict.VERIFIED_READ)

    def test_matching_denial_report(self):
        result = {**BASE, 'get_object_outcome':'GET_OBJECT_ACCESS_DENIED', 'aws_error_code':'AccessDenied'}
        self.assertEqual(interpret_probe(result, EXPECTED), ProbeVerdict.VERIFIED_DENIAL)

    def test_wrong_role_or_account_fails_closed(self):
        for arn in ('arn:aws:sts::111122223333:assumed-role/other/session',
                    'arn:aws:sts::999922223333:assumed-role/probe/session',
                    'arn:aws:iam::111122223333:user/admin'):
            with self.subTest(arn=arn):
                self.assertEqual(interpret_probe({**BASE,'assumed_role_session_arn':arn}, EXPECTED), ProbeVerdict.INSUFFICIENT_EVIDENCE)

    def test_wrong_object_or_region_fails_closed(self):
        for field,value in (('bucket','other'),('key','fixture/other'),('region','eu-west-1')):
            with self.subTest(field=field):
                self.assertEqual(interpret_probe({**BASE,field:value}, EXPECTED), ProbeVerdict.INSUFFICIENT_EVIDENCE)

    def test_inconsistent_error_fails_closed(self):
        self.assertEqual(interpret_probe({**BASE,'aws_error_code':'AccessDenied'}, EXPECTED), ProbeVerdict.INSUFFICIENT_EVIDENCE)

if __name__ == '__main__':
    unittest.main()
