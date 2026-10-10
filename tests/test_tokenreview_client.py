import unittest
from cpal.tokenreview_client import authenticate_collector


class TokenReviewClientTests(unittest.TestCase):
    def test_no_http_downgrade(self):
        result = authenticate_collector(api_url='http://127.0.0.1', cluster_ca='/ca', verifier_token='v', candidate_token='c', expected_username='u', expected_uid='id', audience='a')
        self.assertEqual(result.reason, 'MISSING_TRUST_CONFIGURATION')

    def test_missing_trust_anchor(self):
        result = authenticate_collector(api_url='https://127.0.0.1', cluster_ca='', verifier_token='v', candidate_token='c', expected_username='u', expected_uid='id', audience='a')
        self.assertEqual(result.reason, 'MISSING_TRUST_CONFIGURATION')

    def test_unavailable_ca_fails_closed(self):
        result = authenticate_collector(api_url='https://127.0.0.1', cluster_ca='/definitely/not/a/ca', verifier_token='v', candidate_token='c', expected_username='u', expected_uid='id', audience='a')
        self.assertFalse(result.authenticated)
        self.assertEqual(result.reason, 'TOKENREVIEW_UNAVAILABLE')


if __name__ == '__main__':
    unittest.main()
