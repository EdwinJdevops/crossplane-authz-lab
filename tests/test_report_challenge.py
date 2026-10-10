import hashlib
import os
import tempfile
import unittest

from cpal.report_challenge import validate_report
from cpal.sqlite_replay import SQLiteReplayLedger


class ReportChallengeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = SQLiteReplayLedger(os.path.join(self.temp.name, 'nonces.sqlite'))
        self.report = b'{"observation":"scoped"}'
        self.envelope = dict(principal='collector', nonce='fresh-1', execution_id='execution-1', report_sha256=hashlib.sha256(self.report).hexdigest(), expires_at=1100)
        self.options = dict(authenticated_principal='collector', expected_principal='collector', expected_nonce='fresh-1', expected_execution='execution-1', ledger=self.ledger, now=1000)

    def check(self, report=None, envelope=None, **changes):
        return validate_report(self.report if report is None else report, self.envelope if envelope is None else envelope, **{**self.options, **changes})

    def test_accept_once(self):
        self.assertTrue(self.check().accepted)
        self.assertEqual(self.check().reason, 'REPLAY_DETECTED')

    def test_tampered_report(self):
        self.assertEqual(self.check(report=b'changed').reason, 'REPORT_DIGEST_MISMATCH')

    def test_wrong_identity(self):
        self.assertEqual(self.check(authenticated_principal='attacker').reason, 'UNAUTHENTICATED_OR_WRONG_PRINCIPAL')

    def test_wrong_execution(self):
        self.assertEqual(self.check(expected_execution='other').reason, 'CHALLENGE_BINDING_MISMATCH')

    def test_expired(self):
        self.assertEqual(self.check(now=1100).reason, 'CHALLENGE_EXPIRED_OR_TOO_LONG')

    def test_missing_authentication(self):
        self.assertEqual(self.check(authenticated_principal=None).reason, 'UNAUTHENTICATED_OR_WRONG_PRINCIPAL')

    def test_extra_envelope_fields(self):
        self.assertEqual(self.check(envelope={**self.envelope, 'ignored':'x'}).reason, 'INVALID_ENVELOPE')

    def test_storage_failure(self):
        class Broken:
            def consume(self, *args): raise OSError('storage unavailable')
        self.assertEqual(self.check(ledger=Broken()).reason, 'REPLAY_STORE_UNAVAILABLE')


if __name__ == '__main__':
    unittest.main()
