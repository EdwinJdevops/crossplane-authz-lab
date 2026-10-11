import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch

from cpal.sqlite_replay import SQLiteReplayLedger
from cpal.tokenreview_result import TokenReviewResult
from cpal.verified_report import verify_report


class VerifiedReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.report = b'actual report bytes'
        self.envelope = dict(principal='collector', nonce='nonce-1', execution_id='execution-1', report_sha256=hashlib.sha256(self.report).hexdigest(), expires_at=1100)
        self.kwargs = dict(report=self.report, envelope=self.envelope, candidate_token='candidate', api_url='https://cluster', cluster_ca='/ca', verifier_token='verifier', expected_username='collector', expected_uid='uid', audience='aud', expected_nonce='nonce-1', expected_execution='execution-1', ledger=SQLiteReplayLedger(os.path.join(self.temp.name, 'db')), now=1000)

    @patch('cpal.verified_report.authenticate_collector', return_value=TokenReviewResult(False, None, 'TOKEN_NOT_AUTHENTICATED'))
    def test_reject_auth_failure(self, mock_auth):
        result = verify_report(**self.kwargs)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, 'IDENTITY_TOKEN_NOT_AUTHENTICATED')

    @patch('cpal.verified_report.authenticate_collector', return_value=TokenReviewResult(True, 'collector', 'TOKENREVIEW_IDENTITY_MATCHED'))
    def test_report_and_replay(self, mock_auth):
        self.assertTrue(verify_report(**self.kwargs).accepted)
        self.assertEqual(verify_report(**self.kwargs).reason, 'REPLAY_DETECTED')

    @patch('cpal.verified_report.authenticate_collector', return_value=TokenReviewResult(True, 'collector', 'TOKENREVIEW_IDENTITY_MATCHED'))
    def test_tampering(self, mock_auth):
        self.assertEqual(verify_report(**{**self.kwargs, 'report':b'altered'}).reason, 'REPORT_DIGEST_MISMATCH')


if __name__ == '__main__':
    unittest.main()
