import os
import tempfile
import unittest

from cpal.attestation import sign, verify_with_ledger
from cpal.sqlite_replay import SQLiteReplayLedger


class ReplayTests(unittest.TestCase):
    def test_persistent_duplicate_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'replay.sqlite')
            first = SQLiteReplayLedger(path)
            self.assertTrue(first.consume('nonce-a', 1100, 1000))
            second = SQLiteReplayLedger(path)
            self.assertFalse(second.consume('nonce-a', 1100, 1000))
            self.assertTrue(second.consume('nonce-b', 1100, 1000))

    def test_verifier_consumes_once(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = SQLiteReplayLedger(os.path.join(directory, 'replay.sqlite'))
            payload = dict(version=1, collector='test', execution_id='e', state_digest='s', policy_digest='p', nonce='n', issued_at=1000, expires_at=1100, observation_digest='o')
            key = b'k' * 32
            kwargs = dict(ledger=ledger, execution_id='e', state_digest='s', policy_digest='p', nonce='n', now=1050)
            self.assertTrue(verify_with_ledger(payload, sign(payload, key), key, **kwargs).accepted)
            self.assertEqual(verify_with_ledger(payload, sign(payload, key), key, **kwargs).reason, 'REPLAY_DETECTED')

    def test_invalid_signature_does_not_consume(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = SQLiteReplayLedger(os.path.join(directory, 'replay.sqlite'))
            payload = dict(version=1, collector='test', execution_id='e', state_digest='s', policy_digest='p', nonce='n', issued_at=1000, expires_at=1100, observation_digest='o')
            key = b'k' * 32
            kwargs = dict(ledger=ledger, execution_id='e', state_digest='s', policy_digest='p', nonce='n', now=1050)
            self.assertFalse(verify_with_ledger(payload, 'bad', key, **kwargs).accepted)
            self.assertTrue(verify_with_ledger(payload, sign(payload, key), key, **kwargs).accepted)


if __name__ == '__main__':
    unittest.main()
