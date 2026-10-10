import unittest
from cpal.coverage import DependencyCoverage, evaluate_with_coverage
from cpal.evidence import BoundAuthorization, Evidence, current_digests, digest_state
from cpal.model import Decision

OP = digest_state('deploy-api')
STATE = {'k8s:service/api': 'ClusterIP', 'aws:iam/api-role': 'read:none'}
DIGESTS = current_digests(STATE)


def auth(*subjects):
    return BoundAuthorization('authz-coverage', OP, tuple(Evidence('ev-'+s, s, DIGESTS[s]) for s in subjects))


class CoverageTests(unittest.TestCase):
    def test_missing_bound_dependency_is_unknown(self):
        result = evaluate_with_coverage(auth('k8s:service/api'), DIGESTS, OP,
            DependencyCoverage(frozenset(STATE), complete=True))
        self.assertEqual(result.decision, Decision.INSUFFICIENT_EVIDENCE)
        self.assertEqual(result.missing_subjects, ('aws:iam/api-role',))

    def test_unproven_completeness_is_unknown(self):
        result = evaluate_with_coverage(auth(*STATE), DIGESTS, OP,
            DependencyCoverage(frozenset(STATE), complete=False))
        self.assertEqual(result.decision, Decision.INSUFFICIENT_EVIDENCE)

    def test_explicit_unknown_dependency_is_unknown(self):
        result = evaluate_with_coverage(auth(*STATE), DIGESTS, OP,
            DependencyCoverage(frozenset(STATE), ('aws:unknown/path',), complete=True))
        self.assertEqual(result.decision, Decision.INSUFFICIENT_EVIDENCE)

    def test_complete_bound_unchanged_state_allows(self):
        result = evaluate_with_coverage(auth(*STATE), DIGESTS, OP,
            DependencyCoverage(frozenset(STATE), complete=True))
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_complete_bound_changed_state_denies(self):
        changed = dict(STATE)
        changed['aws:iam/api-role'] = 'read:protected-s3'
        result = evaluate_with_coverage(auth(*STATE), current_digests(changed), OP,
            DependencyCoverage(frozenset(STATE), complete=True))
        self.assertEqual(result.decision, Decision.DENY)

if __name__ == '__main__':
    unittest.main()
