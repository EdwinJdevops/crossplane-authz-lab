import os
import tempfile
import unittest

from cpal.attestation import sign
from cpal.evidence_gate import CollectorIdentity, evaluate_evidence
from cpal.sqlite_replay import SQLiteReplayLedger


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = SQLiteReplayLedger(os.path.join(self.temp.name, 'ledger.db'))
        self.key = b'k' * 32
        self.payload = dict(version=1, collector='collector-A', execution_id='e', state_digest='s', policy_digest='p', nonce='n', issued_at=1000, expires_at=1100, observation_digest='o')
        self.signature = sign(self.payload, self.key)
        self.kwargs = dict(expected_principal='collector-A', ledger=self.ledger, execution_id='e', state_digest='s', policy_digest='p', nonce='n', now=1050)

    def check(self, identity, payload=None, signature=None):
        return evaluate_evidence(self.payload if payload is None else payload, self.signature if signature is None else signature, self.key, identity=identity, **self.kwargs)

    def test_missing_identity(self):
        self.assertEqual(self.check(None).reason, 'UNAUTHENTICATED_COLLECTOR')

    def test_unauthenticated_identity(self):
        self.assertEqual(self.check(CollectorIdentity('collector-A', False, 'untrusted')).reason, 'UNAUTHENTICATED_COLLECTOR')

    def test_wrong_identity(self):
        self.assertEqual(self.check(CollectorIdentity('collector-B', True, 'test')).reason, 'COLLECTOR_IDENTITY_MISMATCH')

    def test_matching_asserted_identity_and_replay(self):
        identity = CollectorIdentity('collector-A', True, 'test-only-assertion')
        self.assertEqual(self.check(identity).reason, 'INDEPENDENT_COLLECTOR_ATTESTATION_REQUIRED')
        self.assertEqual(self.check(identity).reason, 'REPLAY_DETECTED')

    def test_bad_signature(self):
        self.assertEqual(self.check(CollectorIdentity('collector-A', True, 'test'), signature='0'*64).reason, 'INVALID_SIGNATURE')


if __name__ == '__main__':
    unittest.main()
