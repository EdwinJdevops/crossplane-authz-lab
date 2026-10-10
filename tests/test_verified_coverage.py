import json
import unittest
from pathlib import Path

from cpal.verified_coverage import assess_e1_coverage
from cpal.model import Decision
from cpal.coverage import evaluate_with_coverage
from cpal.evidence import BoundAuthorization, Evidence, digest_state

ROOT = Path(__file__).resolve().parents[1]

class VerifiedCoverageTests(unittest.TestCase):
    def setUp(self):
        self.objects = json.loads((ROOT / 'fixtures/e1/kubernetes.json').read_text())

    def test_manifest_graph_alone_cannot_certify_complete_coverage(self):
        result = assess_e1_coverage(self.objects, 'api', 'prod')
        self.assertFalse(result.coverage.complete)
        self.assertTrue(result.coverage.unknown_dependencies)

    def test_subject_names_from_external_sources_are_not_proof(self):
        result = assess_e1_coverage(self.objects, 'api', 'prod',
            verified_network_subjects=['aws:network/path'], verified_data_subjects=['aws:iam/role'])
        self.assertFalse(result.coverage.complete)
        self.assertIn('effective AWS authorization and network dependency closure not independently established', result.coverage.unknown_dependencies)

    def test_gate_never_allows_based_only_on_manifest_graph(self):
        result = assess_e1_coverage(self.objects, 'api', 'prod')
        subjects = sorted(result.coverage.required_subjects) or ['synthetic:unrelated']
        auth = BoundAuthorization('a', digest_state('operation'), tuple(
            Evidence(str(i), subject, digest_state(subject)) for i, subject in enumerate(subjects)))
        current = {subject: digest_state(subject) for subject in subjects}
        decision = evaluate_with_coverage(auth, current, auth.operation_digest, result.coverage)
        self.assertEqual(decision.decision, Decision.INSUFFICIENT_EVIDENCE)

if __name__ == '__main__':
    unittest.main()
