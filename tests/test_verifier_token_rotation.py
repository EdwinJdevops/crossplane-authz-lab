import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from cpal.report_http import make_handler


class TokenRotationTests(unittest.TestCase):
    def test_rotating_verifier_token_and_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            token_file = os.path.join(directory, 'token')
            with open(token_file, 'w') as handle:
                handle.write('first')
            observed = []
            def authenticate(**kwargs):
                observed.append(kwargs['verifier_token'])
                return type('Identity', (), {'authenticated': False, 'principal': None})()
            handler = make_handler(api_url='https://kubernetes', cluster_ca='ca', verifier_token='', verifier_token_path=token_file, expected_username='collector', expected_uid='uid', audience='aud', challenge_store=object())
            server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            def submit():
                connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                try:
                    connection.request('POST', '/challenge', body=b'', headers={'Authorization': 'Bearer candidate', 'Content-Length': '0'})
                    response = connection.getresponse()
                    response.read()
                    return response.status
                finally:
                    connection.close()
            try:
                with patch('cpal.challenge_issuer.authenticate_collector', side_effect=authenticate):
                    self.assertEqual(submit(), 403)
                    with open(token_file, 'w') as handle:
                        handle.write('second')
                    self.assertEqual(submit(), 403)
                    os.unlink(token_file)
                    self.assertEqual(submit(), 503)
                self.assertEqual(observed, ['first', 'second'])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
