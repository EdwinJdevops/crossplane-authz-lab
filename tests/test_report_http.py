import http.client
import threading
import unittest
from http.server import ThreadingHTTPServer
from cpal.report_http import make_handler


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(api_url='https://cluster', cluster_ca='/ca', verifier_token='verifier', expected_username='collector', expected_uid='uid', audience='aud', challenge_store=None))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def post(self, path, headers=None, body=b'{}'):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            conn.request('POST', path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status
        finally:
            conn.close()

    def test_no_token(self):
        self.assertEqual(self.post('/reports'), 401)

    def test_wrong_route(self):
        self.assertEqual(self.post('/invalid'), 404)

    def test_oversized(self):
        self.assertEqual(self.post('/reports', {'Content-Length':'131073'}), 413)

    def test_malformed_with_token(self):
        self.assertEqual(self.post('/reports', {'Authorization':'Bearer candidate'}, b'not-json'), 403)


if __name__ == '__main__':
    unittest.main()
