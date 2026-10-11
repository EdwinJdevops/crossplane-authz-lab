"""Experimental TLS transport for verifier report ingress.

Requires trusted server certificate and private key provisioned out of band.
No insecure HTTP fallback. Not a production service by itself.
"""

import ssl
from http.server import ThreadingHTTPServer

from cpal.report_http import make_handler


def make_tls_server(*, host: str, port: int, certfile: str, keyfile: str, **handler_config):
    if not isinstance(host, str) or not host or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError('invalid TLS bind address')
    if not certfile or not keyfile:
        raise ValueError('TLS certificate and private key required')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    server = ThreadingHTTPServer((host, port), make_handler(**handler_config))
    try:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    except BaseException:
        server.server_close()
        raise
    return server
