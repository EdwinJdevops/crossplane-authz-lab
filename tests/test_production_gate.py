"""Release safety regression: prototype evidence must never authorize mutations."""
import unittest
from unittest.mock import patch

from cpal.evidence_gate import CollectorIdentity, evaluate_evidence


class ProductionGateTests(unittest.TestCase):
    def test_no_identity_is_denied(self):
        decision = evaluate_evidence({}, '', '', identity=None, expected_principal='collector', ledger=None, execution_id='e', state_digest='s', policy_digest='p', nonce='n')
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.reason, 'UNAUTHENTICATED_COLLECTOR')

    def test_wrong_principal_is_denied(self):
        decision = evaluate_evidence({'collector': 'attacker'}, '', '', identity=CollectorIdentity('attacker', True, 'TokenReview'), expected_principal='collector', ledger=None, execution_id='e', state_digest='s', policy_digest='p', nonce='n')
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.reason, 'COLLECTOR_IDENTITY_MISMATCH')

    @patch('cpal.evidence_gate.verify_with_ledger')
    def test_even_valid_ledger_evidence_is_not_authorization(self, verify):
        verify.return_value.accepted = True
        verify.return_value.reason = 'VALID'
        decision = evaluate_evidence({'collector': 'collector'}, 'signature', 'secret', identity=CollectorIdentity('collector', True, 'TokenReview'), expected_principal='collector', ledger=object(), execution_id='e', state_digest='s', policy_digest='p', nonce='n')
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.reason, 'INDEPENDENT_COLLECTOR_ATTESTATION_REQUIRED')
        verify.assert_called_once()


if __name__ == '__main__':
    unittest.main()
