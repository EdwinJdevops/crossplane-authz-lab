"""Loopback-only development transport for verifier-side report submissions.

NOT a production endpoint: no TLS or client certificate authentication.
Do not expose via a Service, ingress, port-forward or public interface.
"""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cpal.challenge_issuer import issue_authenticated_challenge
from cpal.report_handler import handle_submission
from cpal.report_protocol import MAX_REQUEST_BYTES


def make_handler(*, api_url, cluster_ca, verifier_token, expected_username, expected_uid, audience, challenge_store):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path not in ('/reports', '/challenge'):
                self.send_error(404)
                return
            length = self.headers.get('Content-Length')
            if not length or not length.isdecimal() or int(length) > (0 if self.path == '/challenge' else MAX_REQUEST_BYTES):
                self.send_error(413)
                return
            auth = self.headers.get('Authorization', '')
            if not auth.startswith('Bearer ') or not auth[7:]:
                self.send_error(401)
                return
            self.connection.settimeout(5)
            try:
                body = self.rfile.read(int(length))
            except (TimeoutError, OSError):
                self.close_connection = True
                return
            if len(body) != int(length):
                self.close_connection = True
                return
            config = dict(api_url=api_url, cluster_ca=cluster_ca, verifier_token=verifier_token, expected_username=expected_username, expected_uid=expected_uid, audience=audience, challenge_store=challenge_store, now=int(time.time()))
            if self.path == '/challenge':
                result = issue_authenticated_challenge(candidate_token=auth[7:], **config)
                response = {'accepted': result.accepted, 'reason': result.reason}
                if result.accepted:
                    response.update(nonce=result.nonce, execution_id=result.execution_id, expires_at=result.expires_at)
            else:
                result = handle_submission(body=body, bearer_token=auth[7:], **config)
                response = {'accepted': result.accepted, 'reason': result.reason}
            payload = json.dumps(response).encode()
            self.send_response(200 if result.accepted else 403)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
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
