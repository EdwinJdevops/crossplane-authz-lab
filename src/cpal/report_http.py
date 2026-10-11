"""Loopback-only development transport for verifier-side report submissions.

NOT a production endpoint: no TLS or client certificate authentication.
Do not expose via a Service, ingress, port-forward or public interface.
"""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cpal.report_handler import handle_submission
from cpal.report_protocol import MAX_REQUEST_BYTES


def make_handler(*, api_url, cluster_ca, verifier_token, expected_username, expected_uid, audience, challenge_store):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != '/reports':
                self.send_error(404)
                return
            length = self.headers.get('Content-Length')
            if not length or not length.isdecimal() or int(length) > MAX_REQUEST_BYTES:
                self.send_error(413)
                return
            auth = self.headers.get('Authorization', '')
            if not auth.startswith('Bearer ') or not auth[7:]:
                self.send_error(401)
                return
            body = self.rfile.read(int(length))
            result = handle_submission(body=body, bearer_token=auth[7:], api_url=api_url, cluster_ca=cluster_ca, verifier_token=verifier_token, expected_username=expected_username, expected_uid=expected_uid, audience=audience, challenge_store=challenge_store, now=int(time.time()))
            payload = json.dumps({'accepted':result.accepted, 'reason':result.reason}).encode()
            self.send_response(200 if result.accepted else 403)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            # Avoid logging untrusted headers or bearer tokens.
            pass

    return Handler


def serve_loopback(*, port: int, **kwargs):
    if not 1 <= port <= 65535:
        raise ValueError('invalid port')
    server = ThreadingHTTPServer(('127.0.0.1', port), make_handler(**kwargs))
    server.serve_forever()
