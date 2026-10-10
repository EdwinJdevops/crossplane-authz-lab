import unittest
from cpal.collector_contract import CollectorExpectation, validate_collector_report
from cpal.live_probe_binding import ExpectedProbe, ProbeVerdict

EXPECT = CollectorExpectation('execution-1', 'collector-a',
    ExpectedProbe('arn:aws:iam::111122223333:role/probe', 'bucket', 'object', 'us-east-1'))
REPORT = {'execution_id':'execution-1','collector_identity':'collector-a',
    'assumed_role_session_arn':'arn:aws:sts::111122223333:assumed-role/probe/session',
    'bucket':'bucket','key':'object','region':'us-east-1',
    'get_object_outcome':'GET_OBJECT_SUCCEEDED','aws_error_code':None}

class CollectorContractTests(unittest.TestCase):
    def test_matching_but_untrusted_report_is_not_authorized(self):
        self.assertEqual(validate_collector_report(REPORT, EXPECT), ProbeVerdict.INSUFFICIENT_EVIDENCE)

    def test_wrong_execution_or_collector_is_rejected(self):
        for field,value in (('execution_id','execution-2'),('collector_identity','forged')):
            with self.subTest(field=field):
                self.assertEqual(validate_collector_report({**REPORT,field:value}, EXPECT), ProbeVerdict.INSUFFICIENT_EVIDENCE)

    def test_wrong_aws_object_is_rejected(self):
        self.assertEqual(validate_collector_report({**REPORT,'key':'other'}, EXPECT), ProbeVerdict.INSUFFICIENT_EVIDENCE)

if __name__ == '__main__':
    unittest.main()
