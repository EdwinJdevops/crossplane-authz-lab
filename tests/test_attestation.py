import unittest

from cpal.attestation import sign, verify


class AttestationTests(unittest.TestCase):
    def setUp(self):
        self.key = b"a" * 32
        self.payload = dict(version=1, collector="local-test", execution_id="exec-1", state_digest="state-1", policy_digest="policy-1", nonce="nonce-1", issued_at=1000, expires_at=1100, observation_digest="observation-1")
        self.signature = sign(self.payload, self.key)
        self.expected = dict(execution_id="exec-1", state_digest="state-1", policy_digest="policy-1", nonce="nonce-1", now=1050)

    def check(self, payload=None, signature=None, store=None, **changes):
        args = {**self.expected, **changes}
        return verify(self.payload if payload is None else payload, self.signature if signature is None else signature, self.key, consumed_nonces=set() if store is None else store, **args)

    def test_valid_and_replay(self):
        store = set()
        self.assertTrue(self.check(store=store).accepted)
        self.assertEqual(self.check(store=store).reason, "REPLAY_DETECTED")

    def test_missing_store_fails_closed(self):
        self.assertEqual(verify(self.payload, self.signature, self.key, **self.expected).reason, "REPLAY_STORE_REQUIRED")

    def test_tampering(self):
        self.assertEqual(self.check(payload={**self.payload, "observation_digest": "tampered"}).reason, "INVALID_SIGNATURE")

    def test_wrong_key_signature(self):
        self.assertEqual(self.check(signature="0" * 64).reason, "INVALID_SIGNATURE")

    def test_execution_and_nonce_binding(self):
        self.assertEqual(self.check(execution_id="exec-2").reason, "BINDING_MISMATCH")
        self.assertEqual(self.check(nonce="nonce-2").reason, "BINDING_MISMATCH")

    def test_expired_and_future(self):
        self.assertEqual(self.check(now=1100).reason, "EXPIRED_OR_INVALID_WINDOW")
        self.assertEqual(self.check(now=900).reason, "EXPIRED_OR_INVALID_WINDOW")

    def test_extra_field(self):
        self.assertEqual(self.check(payload={**self.payload, "extra": "x"}).reason, "INVALID_SCHEMA")

    def test_reject_boolean_timestamp(self):
        self.assertEqual(self.check(payload={**self.payload, "issued_at": True}).reason, "INVALID_TIMESTAMPS")


if __name__ == "__main__":
    unittest.main()
