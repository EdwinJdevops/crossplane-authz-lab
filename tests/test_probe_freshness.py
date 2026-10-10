import unittest
from cpal.probe_freshness import FreshnessVerdict, ProbeBinding, check_probe_freshness

BINDING = ProbeBinding('run-1', 'state-v1', 'policy-v1')
REPORT = {'execution_id':'run-1','state_digest':'state-v1','policy_digest':'policy-v1'}


class ProbeFreshnessTests(unittest.TestCase):
    def test_matching_is_not_authenticated(self):
        self.assertEqual(check_probe_freshness(REPORT, BINDING), FreshnessVerdict.MATCHED_UNAUTHENTICATED)

    def test_replay_from_other_execution_is_rejected(self):
        self.assertEqual(check_probe_freshness(REPORT, ProbeBinding('run-2','state-v1','policy-v1')),
                         FreshnessVerdict.INSUFFICIENT_EVIDENCE)

    def test_changed_state_or_policy_is_rejected(self):
        for binding in (ProbeBinding('run-1','state-v2','policy-v1'), ProbeBinding('run-1','state-v1','policy-v2')):
            with self.subTest(binding=binding):
                self.assertEqual(check_probe_freshness(REPORT,binding), FreshnessVerdict.INSUFFICIENT_EVIDENCE)

    def test_missing_fields_are_rejected(self):
        for field in REPORT:
            with self.subTest(field=field):
                self.assertEqual(check_probe_freshness({k:v for k,v in REPORT.items() if k!=field},BINDING),
                                 FreshnessVerdict.INSUFFICIENT_EVIDENCE)

    def test_empty_expectation_is_rejected(self):
        self.assertEqual(check_probe_freshness(REPORT, ProbeBinding('','state-v1','policy-v1')),
                         FreshnessVerdict.INSUFFICIENT_EVIDENCE)

if __name__ == '__main__': unittest.main()
