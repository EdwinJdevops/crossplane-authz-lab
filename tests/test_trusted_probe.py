import unittest
from cpal.live_probe_binding import ExpectedProbe, ProbeVerdict
from cpal.trusted_probe import ProbeProvenance, evaluate_trusted_probe

EXPECTED = ExpectedProbe('arn:aws:iam::111122223333:role/probe', 'bucket', 'object', 'us-east-1')
REPORT = {'assumed_role_session_arn':'arn:aws:sts::111122223333:assumed-role/probe/session',
          'bucket':'bucket', 'key':'object', 'region':'us-east-1',
          'get_object_outcome':'GET_OBJECT_SUCCEEDED', 'aws_error_code':None}

class TrustedProbeTests(unittest.TestCase):
    def test_missing_provenance_fails_closed(self):
        self.assertEqual(evaluate_trusted_probe(REPORT, EXPECTED, None), ProbeVerdict.INSUFFICIENT_EVIDENCE)

    def test_unverified_provenance_fails_closed(self):
        p = ProbeProvenance(False, 'collector', 'run-1')
        self.assertEqual(evaluate_trusted_probe(REPORT, EXPECTED, p), ProbeVerdict.INSUFFICIENT_EVIDENCE)

    def test_missing_collector_identity_or_execution_id_fails_closed(self):
        for identity, execution in (('', 'run-1'), ('collector', ''), (' ', 'run-1')):
            with self.subTest(identity=identity, execution=execution):
                p = ProbeProvenance(True, identity, execution)
                self.assertEqual(evaluate_trusted_probe(REPORT, EXPECTED, p), ProbeVerdict.INSUFFICIENT_EVIDENCE)

    def test_verified_transport_flag_allows_interpretation_only(self):
        p = ProbeProvenance(True, 'collector', 'run-1')
        self.assertEqual(evaluate_trusted_probe(REPORT, EXPECTED, p), ProbeVerdict.VERIFIED_READ)

if __name__ == '__main__':
    unittest.main()
