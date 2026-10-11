"""Disposable loopback TLS handshake; openssl generates throwaway CA/cert.

This is transport validation only, not an authenticated collector report.
"""
import http.client
import os
import ssl
import subprocess
import tempfile
import threading

from cpal.report_tls import make_tls_server


def run(*args):
    subprocess.run(['openssl', *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        ca_key, ca_crt = os.path.join(tmp, 'ca.key'), os.path.join(tmp, 'ca.crt')
        key, csr, crt = os.path.join(tmp, 'server.key'), os.path.join(tmp, 'server.csr'), os.path.join(tmp, 'server.crt')
        ext = os.path.join(tmp, 'ext.cnf')
        with open(ext, 'w', encoding='utf-8') as file:
            file.write('subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
        run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=cpal-test-ca', '-keyout', ca_key, '-out', ca_crt)
        run('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', key, '-out', csr)
        run('x509', '-req', '-in', csr, '-CA', ca_crt, '-CAkey', ca_key, '-CAcreateserial', '-days', '1', '-out', crt, '-extfile', ext)
        server = make_tls_server(host='127.0.0.1', port=0, certfile=crt, keyfile=key, api_url='https://unused', cluster_ca=ca_crt, verifier_token='unused', expected_username='collector', expected_uid='uid', audience='aud', challenge_store=None)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            trusted = ssl.create_default_context(cafile=ca_crt)
            conn = http.client.HTTPSConnection('localhost', server.server_port, context=trusted, timeout=5)
            conn.request('POST', '/reports', body=b'', headers={'Content-Length':'0'})
            response = conn.getresponse()
            assert response.status == 401, response.status
            response.read()
            conn.close()
            print('TLS: trusted CA and hostname accepted', flush=True)
            untrusted = ssl.create_default_context()
            conn = http.client.HTTPSConnection('localhost', server.server_port, context=untrusted, timeout=5)
            try:
                try:
                    conn.request('POST', '/reports', body=b'', headers={'Content-Length':'0'})
                except ssl.SSLCertVerificationError:
                    print('TLS: untrusted CA rejected', flush=True)
                else:
                    raise AssertionError('untrusted server certificate accepted')
            finally:
                conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    main()
