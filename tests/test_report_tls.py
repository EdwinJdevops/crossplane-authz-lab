import unittest
from cpal.report_tls import make_tls_server


class TLSTransportTests(unittest.TestCase):
    def test_missing_certificate_rejected(self):
        with self.assertRaises(ValueError):
            make_tls_server(host='127.0.0.1', port=0, certfile='', keyfile='')

    def test_invalid_port_rejected(self):
        with self.assertRaises(ValueError):
            make_tls_server(host='127.0.0.1', port=-1, certfile='cert', keyfile='key')

    def test_missing_files_rejected(self):
        with self.assertRaises(OSError):
            make_tls_server(host='127.0.0.1', port=0, certfile='/not/a/cert', keyfile='/not/a/key')


if __name__ == '__main__':
    unittest.main()
