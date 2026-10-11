import base64
import json
import unittest
from cpal.report_protocol import InvalidSubmission, parse_submission


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.payload = {'report_b64': base64.b64encode(b'bytes').decode(), 'envelope': {'principal':'collector', 'nonce':'nonce', 'execution_id':'exec', 'report_sha256':'digest'}}

    def parse(self, payload):
        return parse_submission(json.dumps(payload).encode())

    def test_valid(self):
        self.assertEqual(self.parse(self.payload)[0], b'bytes')

    def test_reject_identity_override(self):
        with self.assertRaises(InvalidSubmission):
            self.parse({**self.payload, 'authenticated_principal':'attacker'})

    def test_reject_token_in_body(self):
        with self.assertRaises(InvalidSubmission):
            self.parse({**self.payload, 'token':'secret'})

    def test_reject_extra_envelope(self):
        with self.assertRaises(InvalidSubmission):
            self.parse({**self.payload, 'envelope':{**self.payload['envelope'], 'expires_at':999999999}})

    def test_reject_malformed_base64(self):
        with self.assertRaises(InvalidSubmission):
            self.parse({**self.payload, 'report_b64':'!!!!'})

    def test_reject_oversized_request(self):
        with self.assertRaises(InvalidSubmission):
            parse_submission(b'x' * 131073)

    def test_reject_oversized_report(self):
        with self.assertRaises(InvalidSubmission):
            self.parse({**self.payload, 'report_b64':base64.b64encode(b'x' * 65537).decode()})


if __name__ == '__main__':
    unittest.main()
