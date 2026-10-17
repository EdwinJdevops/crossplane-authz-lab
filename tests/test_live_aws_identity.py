import unittest
from scripts.verify_live_aws_identity import verify_identity


class StubSTS:
    def __init__(self, account, arn, user='session'):
        self.response = {'Account':account,'Arn':arn,'UserId':user}
    def get_caller_identity(self):
        return self.response


class STSIdentityTests(unittest.TestCase):
    def setUp(self):
        self.account = '123456789012'
        self.arn = 'arn:aws:sts::123456789012:assumed-role/cpal-verifier/session'
    def test_exact_assumed_role_accepted(self):
        self.assertTrue(verify_identity(StubSTS(self.account,self.arn),expected_account=self.account,expected_arn=self.arn))
    def test_wrong_account_denied(self):
        self.assertFalse(verify_identity(StubSTS('999999999999',self.arn),expected_account=self.account,expected_arn=self.arn))
    def test_wrong_session_denied(self):
        self.assertFalse(verify_identity(StubSTS(self.account,self.arn+'-other'),expected_account=self.account,expected_arn=self.arn))
    def test_iam_user_denied(self):
        arn='arn:aws:iam::123456789012:user/developer'
        self.assertFalse(verify_identity(StubSTS(self.account,arn),expected_account=self.account,expected_arn=arn))
    def test_missing_session_id_denied(self):
        self.assertFalse(verify_identity(StubSTS(self.account,self.arn,''),expected_account=self.account,expected_arn=self.arn))


if __name__ == '__main__':
    unittest.main()
