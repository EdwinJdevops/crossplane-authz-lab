import unittest
from cpal.live_probe_binding import ProbeVerdict
from scripts.validate_probe_pair import validate_pair

ROLE='arn:aws:iam::111122223333:role/probe'
BASE={'assumed_role_session_arn':'arn:aws:sts::111122223333:assumed-role/probe/session',
      'bucket':'bucket','region':'us-east-1'}
GOOD={**BASE,'key':'allowed','get_object_outcome':'GET_OBJECT_SUCCEEDED','aws_error_code':None}
DENIED={**BASE,'key':'denied','get_object_outcome':'GET_OBJECT_ACCESS_DENIED','aws_error_code':'AccessDenied'}

class PairTests(unittest.TestCase):
    def test_expected_positive_and_negative(self):
        self.assertTrue(validate_pair(GOOD,DENIED,ROLE,'bucket','allowed','denied','us-east-1'))

    def test_negative_control_that_succeeds_is_failure(self):
        self.assertFalse(validate_pair(GOOD,{**DENIED,'get_object_outcome':'GET_OBJECT_SUCCEEDED','aws_error_code':None},ROLE,'bucket','allowed','denied','us-east-1'))

    def test_wrong_role_or_object_is_failure(self):
        self.assertFalse(validate_pair(GOOD,DENIED,ROLE,'bucket','wrong','denied','us-east-1'))
        self.assertFalse(validate_pair(GOOD,DENIED,'arn:aws:iam::999999999999:role/probe','bucket','allowed','denied','us-east-1'))

if __name__ == '__main__': unittest.main()
