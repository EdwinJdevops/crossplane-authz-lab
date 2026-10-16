import unittest
from cpal.report_protocol import InvalidSubmission, parse_submission


class AmbiguousJSONTests(unittest.TestCase):
    def test_duplicate_top_level_key(self):
        with self.assertRaisesRegex(InvalidSubmission, 'INVALID_JSON'):
            parse_submission(b'{"report_b64":"","report_b64":"AA==","envelope":{}}')

    def test_duplicate_envelope_key(self):
        with self.assertRaisesRegex(InvalidSubmission, 'INVALID_JSON'):
            parse_submission(b'{"report_b64":"AA==","envelope":{"principal":"a","principal":"b"}}')

    def test_nonfinite_json_constant(self):
        with self.assertRaisesRegex(InvalidSubmission, 'INVALID_JSON'):
            parse_submission(b'{"report_b64":"AA==","envelope":NaN}')


if __name__ == '__main__':
    unittest.main()
