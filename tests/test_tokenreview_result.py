import unittest
from cpal.tokenreview_result import validate_tokenreview


class TokenReviewResultTests(unittest.TestCase):
    def setUp(self):
        self.response = dict(apiVersion='authentication.k8s.io/v1', kind='TokenReview', status=dict(authenticated=True, user=dict(username='system:serviceaccount:ns:collector', uid='uid-1'), audiences=['cpal-audience']))
        self.expected = dict(expected_username='system:serviceaccount:ns:collector', expected_uid='uid-1', expected_audience='cpal-audience')

    def check(self, response=None, **kwargs):
        return validate_tokenreview(self.response if response is None else response, **{**self.expected, **kwargs})

    def test_valid_response(self):
        self.assertTrue(self.check().authenticated)

    def test_wrong_uid(self):
        self.assertEqual(self.check(expected_uid='uid-2').reason, 'IDENTITY_MISMATCH')

    def test_wrong_audience(self):
        self.assertEqual(self.check(expected_audience='other').reason, 'AUDIENCE_MISMATCH')

    def test_unauthenticated(self):
        self.assertEqual(self.check(response={**self.response, 'status': {'authenticated': False}}).reason, 'TOKEN_NOT_AUTHENTICATED')

    def test_missing_uid(self):
        self.assertEqual(self.check(response={**self.response, 'status': {**self.response['status'], 'user': {'username': self.expected['expected_username']}}}).reason, 'IDENTITY_MISMATCH')

    def test_wrong_kind(self):
        self.assertEqual(self.check(response={**self.response, 'kind':'Other'}).reason, 'INVALID_TOKENREVIEW_RESPONSE')


if __name__ == '__main__':
    unittest.main()
