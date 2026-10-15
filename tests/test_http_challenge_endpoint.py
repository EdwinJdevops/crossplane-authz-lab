import http.client
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer
from cpal.challenge_store import ChallengeStore
from cpal.report_http import make_handler
from cpal.tokenreview_result import TokenReviewResult


class HTTPChallengeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = ChallengeStore(os.path.join(self.tmp.name, 'db.sqlite'))
        handler = make_handler(api_url='https://kubernetes', cluster_ca='ca', verifier_token='verifier', expected_username='system:serviceaccount:ns:collector', expected_uid='uid', audience='aud', challenge_store=self.store)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.cleanup_server)

    def cleanup_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, body=b'', token='valid'):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            headers = {'Content-Length': str(len(body))}
            if token is not None:
                headers['Authorization'] = 'Bearer ' + token
            connection.request('POST', '/challenge', body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if response.getheader('Content-Type') == 'application/json' else raw
        finally:
            connection.close()

    def test_missing_bearer_rejected(self):
        status, _ = self.request(token=None)
        self.assertEqual(status, 401)

    def test_client_supplied_identity_rejected(self):
        status, _ = self.request(body=b'{"principal":"admin"}')
        self.assertEqual(status, 413)

    def test_bad_token_cannot_issue(self):
        with patch('cpal.challenge_issuer.authenticate_collector', return_value=TokenReviewResult(False, None, 'INVALID')):
            status, response = self.request()
        self.assertEqual(status, 403)
        self.assertFalse(response['accepted'])
        self.assertNotIn('nonce', response)

    def test_valid_token_gets_verifier_owned_challenge(self):
        with patch('cpal.challenge_issuer.authenticate_collector', return_value=TokenReviewResult(True, 'system:serviceaccount:ns:collector', 'OK')):
            status, response = self.request()
        self.assertEqual(status, 200)
        self.assertTrue(response['nonce'])
        self.assertTrue(response['execution_id'])
        self.assertTrue(self.store.consume(nonce=response['nonce'], principal='system:serviceaccount:ns:collector', execution_id=response['execution_id']))


if __name__ == '__main__':
    unittest.main()
