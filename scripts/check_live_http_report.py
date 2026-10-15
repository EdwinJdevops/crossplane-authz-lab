"""Disposable kind live TokenReview via loopback-only HTTP verifier prototype."""
import base64
import hashlib
import http.client
import json
import os
import subprocess
import tempfile
import threading
import time

from cpal.challenge_store import ChallengeStore
from cpal.report_http import make_handler
from http.server import ThreadingHTTPServer


def k(*args):
    return subprocess.check_output(['kubectl', *args], text=True).strip()


def main():
    ns = 'cpal-experiment'
    principal = f'system:serviceaccount:{ns}:cpal-collector'
    audience = 'cpal-collector-verification'
    collector_token = k('-n', ns, 'create', 'token', 'cpal-collector', '--audience=' + audience, '--duration=10m')
    verifier_token = k('-n', ns, 'create', 'token', 'cpal-token-verifier', '--duration=10m')
    uid = k('-n', ns, 'get', 'sa', 'cpal-collector', '-o', 'jsonpath={.metadata.uid}')
    ca = k('-n', ns, 'get', 'cm', 'kube-root-ca.crt', '-o', 'jsonpath={.data.ca\\.crt}')
    endpoint = k('config', 'view', '--minify', '-o', 'jsonpath={.clusters[0].cluster.server}')
    with tempfile.TemporaryDirectory() as tmp:
        ca_path = os.path.join(tmp, 'ca.crt')
        with open(ca_path, 'w', encoding='utf-8') as file:
            file.write(ca)
        store = ChallengeStore(os.path.join(tmp, 'challenges.db'))
        report = b'{"observed":"pod","source":"http-integration"}'
        handler = make_handler(api_url=endpoint, cluster_ca=ca_path, verifier_token=verifier_token, expected_username=principal, expected_uid=uid, audience=audience, challenge_store=store)
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def send(path, payload, token):
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=15)
            try:
                connection.request('POST', path, body=payload, headers={'Authorization':'Bearer '+token, 'Content-Type':'application/json'})
                response = connection.getresponse()
                return response.status, json.loads(response.read())
            finally:
                connection.close()
        try:
            status, result = send('/challenge', b'', 'invalid-token')
            assert status == 403 and not result['accepted'] and 'nonce' not in result, result
            print('HTTP live verifier: invalid token cannot issue challenge', flush=True)
            status, challenge = send('/challenge', b'', collector_token)
            assert status == 200 and challenge['accepted'] and challenge['nonce'] and challenge['execution_id'], challenge
            print('HTTP live verifier: authenticated challenge issued by verifier', flush=True)
            envelope = {'principal':principal, 'nonce':challenge['nonce'], 'execution_id':challenge['execution_id'], 'report_sha256':hashlib.sha256(report).hexdigest()}
            body = json.dumps({'report_b64':base64.b64encode(report).decode(), 'envelope':envelope}).encode()
            status, result = send('/reports', body, 'invalid-token')
            assert status == 403 and not result['accepted'], result
            print('HTTP live verifier: invalid token cannot submit report', flush=True)
            status, result = send('/reports', body, collector_token)
            assert status == 200 and result['accepted'], result
            print('HTTP live verifier: authenticated report accepted', flush=True)
            status, result = send('/reports', body, collector_token)
            assert status == 403 and result['reason'] == 'CHALLENGE_NOT_VALID_OR_ALREADY_USED', result
            print('HTTP live verifier: replay rejected', flush=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    main()
