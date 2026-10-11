import os
import tempfile
import unittest
from unittest.mock import patch
from cpal.challenge_issuer import issue_authenticated_challenge
from cpal.challenge_store import ChallengeStore
from cpal.tokenreview_result import TokenReviewResult


class ChallengeIssuerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ChallengeStore(os.path.join(self.temp.name, 'challenges.db'))
        self.config = dict(candidate_token='candidate', api_url='https://kubernetes', cluster_ca='ca', verifier_token='verifier', expected_username='system:serviceaccount:ns:collector', expected_uid='uid', audience='aud', challenge_store=self.store, now=100)

    def test_missing_bearer_rejected_without_review(self):
        with patch('cpal.challenge_issuer.authenticate_collector') as auth:
            result = issue_authenticated_challenge(**{**self.config, 'candidate_token':''})
            self.assertFalse(result.accepted)
            auth.assert_not_called()

    def test_invalid_identity_rejected_without_challenge(self):
        with patch('cpal.challenge_issuer.authenticate_collector', return_value=TokenReviewResult(False, None, 'INVALID')):
            result = issue_authenticated_challenge(**self.config)
        self.assertFalse(result.accepted)
        self.assertIsNone(result.nonce)

    def test_authenticated_identity_gets_server_generated_nonce(self):
        with patch('cpal.challenge_issuer.authenticate_collector', return_value=TokenReviewResult(True, self.config['expected_username'], 'AUTHENTICATED')):
            result = issue_authenticated_challenge(**self.config)
        self.assertTrue(result.accepted)
        self.assertTrue(result.nonce)
        self.assertTrue(result.execution_id)
        self.assertTrue(self.store.consume(nonce=result.nonce, principal=self.config['expected_username'], execution_id=result.execution_id, now=101))
        self.assertFalse(self.store.consume(nonce=result.nonce, principal=self.config['expected_username'], execution_id=result.execution_id, now=101))

    def test_store_failure_fails_closed(self):
        class BrokenStore:
            def issue(self, **kwargs):
                raise OSError('unavailable')
        with patch('cpal.challenge_issuer.authenticate_collector', return_value=TokenReviewResult(True, self.config['expected_username'], 'AUTHENTICATED')):
            result = issue_authenticated_challenge(**{**self.config, 'challenge_store':BrokenStore()})
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, 'CHALLENGE_STORE_UNAVAILABLE')


if __name__ == '__main__':
    unittest.main()
