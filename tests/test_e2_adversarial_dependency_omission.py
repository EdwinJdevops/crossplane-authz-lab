import unittest

from cpal.evidence import BoundAuthorization, Evidence, current_digests, digest_state
from cpal.freshness import evaluate_authorization_freshness
from cpal.model import Decision

OP = digest_state('operation:deploy-api')

class DependencyOmissionTests(unittest.TestCase):
    def test_unbound_material_dependency_can_change_without_detection(self):
        initial = {'aws:iam/api-role': 'read:none', 'k8s:service/api': 'ClusterIP'}
        authorization = BoundAuthorization('authz-omission', OP, (
            Evidence('e1', 'k8s:service/api', current_digests(initial)['k8s:service/api']),
        ))
        changed = dict(initial)
        changed['aws:iam/api-role'] = 'read:protected-s3'
        result = evaluate_authorization_freshness(authorization, current_digests(changed), OP)
        # This is a characterization test, not an assertion that the system is safe.
        # It demonstrates that digest freshness alone cannot discover omitted dependencies.
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_binding_the_dependency_detects_its_change(self):
        initial = {'aws:iam/api-role': 'read:none', 'k8s:service/api': 'ClusterIP'}
        digests = current_digests(initial)
        authorization = BoundAuthorization('authz-complete', OP, (
            Evidence('e1', 'k8s:service/api', digests['k8s:service/api']),
            Evidence('e2', 'aws:iam/api-role', digests['aws:iam/api-role']),
        ))
        changed = dict(initial)
        changed['aws:iam/api-role'] = 'read:protected-s3'
        result = evaluate_authorization_freshness(authorization, current_digests(changed), OP)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.changed_subjects, ('aws:iam/api-role',))

if __name__ == '__main__':
    unittest.main()
