import base64
import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from cpal.challenge_store import ChallengeStore
from cpal.report_handler import handle_submission
from cpal.tokenreview_result import TokenReviewResult


class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        store = ChallengeStore(os.path.join(self.tmp.name, 'db'))
        challenge = store.issue(principal='collector', execution_id='e1', now=1000)
        report = b'observation'
        envelope = {'principal':'collector', 'nonce':challenge.nonce, 'execution_id':'e1', 'report_sha256':hashlib.sha256(report).hexdigest()}
        body = json.dumps({'report_b64':base64.b64encode(report).decode(), 'envelope':envelope}).encode()
        self.kwargs = dict(body=body, bearer_token='candidate', api_url='https://cluster', cluster_ca='/ca', verifier_token='verifier', expected_username='collector', expected_uid='uid', audience='aud', challenge_store=store, now=1001)

    def test_missing_token(self):
        self.assertEqual(handle_submission(**{**self.kwargs, 'bearer_token':''}).reason, 'MISSING_BEARER_TOKEN')

    def test_malformed_body(self):
        self.assertEqual(handle_submission(**{**self.kwargs, 'body':b'bad json'}).reason, 'INVALID_JSON')

    @patch('cpal.challenge_verified_report.authenticate_collector', return_value=TokenReviewResult(True, 'collector', 'MATCH'))
    def test_valid_then_replay(self, auth):
        self.assertTrue(handle_submission(**self.kwargs).accepted)
        self.assertEqual(handle_submission(**self.kwargs).reason, 'CHALLENGE_NOT_VALID_OR_ALREADY_USED')

    @patch('cpal.challenge_verified_report.authenticate_collector', return_value=TokenReviewResult(False, None, 'DENIED'))
    def test_auth_failure(self, auth):
        self.assertEqual(handle_submission(**self.kwargs).reason, 'IDENTITY_NOT_VERIFIED')

    @patch('cpal.challenge_verified_report.authenticate_collector', return_value=TokenReviewResult(True, 'collector', 'MATCH'))
    def test_identity_claim_rejected(self, auth):
        obj = json.loads(self.kwargs['body'])
        obj['authenticated_principal'] = 'collector'
        self.assertEqual(handle_submission(**{**self.kwargs, 'body':json.dumps(obj).encode()}).reason, 'INVALID_REQUEST_FIELDS')


if __name__ == '__main__':
    unittest.main()
