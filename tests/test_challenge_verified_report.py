import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch
from cpal.challenge_store import ChallengeStore
from cpal.challenge_verified_report import verify_challenged_report
from cpal.tokenreview_result import TokenReviewResult


class ChallengeVerifiedReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = ChallengeStore(os.path.join(self.tmp.name, 'db'))
        self.challenge = self.store.issue(principal='collector', execution_id='execution', now=1000)
        self.report = b'actual report'
        self.envelope = dict(principal='collector', nonce=self.challenge.nonce, execution_id='execution', report_sha256=hashlib.sha256(self.report).hexdigest())
        self.args = dict(report=self.report, envelope=self.envelope, candidate_token='candidate', api_url='https://cluster', cluster_ca='/ca', verifier_token='verifier', expected_username='collector', expected_uid='uid', audience='aud', challenge_store=self.store, now=1001)

    @patch('cpal.challenge_verified_report.authenticate_collector', return_value=TokenReviewResult(True, 'collector', 'MATCH'))
    def test_valid_once_then_replay(self, auth):
        self.assertTrue(verify_challenged_report(**self.args).accepted)
        self.assertEqual(verify_challenged_report(**self.args).reason, 'CHALLENGE_NOT_VALID_OR_ALREADY_USED')

    @patch('cpal.challenge_verified_report.authenticate_collector', return_value=TokenReviewResult(True, 'collector', 'MATCH'))
    def test_forged_nonce_fails(self, auth):
        forged = {**self.envelope, 'nonce':'attacker-invented'}
        self.assertEqual(verify_challenged_report(**{**self.args, 'envelope':forged}).reason, 'CHALLENGE_NOT_VALID_OR_ALREADY_USED')

    @patch('cpal.challenge_verified_report.authenticate_collector', return_value=TokenReviewResult(True, 'collector', 'MATCH'))
    def test_tamper_does_not_consume(self, auth):
        self.assertEqual(verify_challenged_report(**{**self.args, 'report':b'tampered'}).reason, 'REPORT_DIGEST_MISMATCH')
        self.assertTrue(verify_challenged_report(**self.args).accepted)

    @patch('cpal.challenge_verified_report.authenticate_collector', return_value=TokenReviewResult(False, None, 'REJECTED'))
    def test_auth_failure_does_not_consume(self, auth):
        self.assertEqual(verify_challenged_report(**self.args).reason, 'IDENTITY_NOT_VERIFIED')
        self.assertTrue(self.store.consume(nonce=self.challenge.nonce, principal='collector', execution_id='execution', now=1001))

    @patch('cpal.challenge_verified_report.authenticate_collector', return_value=TokenReviewResult(True, 'collector', 'MATCH'))
    def test_expired(self, auth):
        self.assertEqual(verify_challenged_report(**{**self.args, 'now':1201}).reason, 'CHALLENGE_NOT_VALID_OR_ALREADY_USED')


if __name__ == '__main__':
    unittest.main()
