import unittest

from cpal.evidence import BoundAuthorization, Evidence, current_digests, digest_state
from cpal.freshness import evaluate_authorization_freshness
from cpal.model import Decision


OP = digest_state("terraform-plan:sha256:plan-a")


def authorization_for(state: dict[str, str]) -> BoundAuthorization:
    digests = current_digests(state)
    return BoundAuthorization(
        authorization_id="authz-1",
        operation_digest=OP,
        evidence=(
            Evidence("ev-network", "aws:network/api", digests["aws:network/api"]),
            Evidence("ev-iam", "aws:iam/api-role", digests["aws:iam/api-role"]),
            Evidence("ev-k8s", "k8s:service/api", digests["k8s:service/api"]),
        ),
    )


class StaleAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.s0 = {
            "aws:network/api": "private",
            "aws:iam/api-role": "read:protected-s3",
            "k8s:service/api": "ClusterIP",
            "aws:tag/unrelated": "owner=platform",
        }
        self.authz = authorization_for(self.s0)

    def test_unchanged_bound_state_remains_authorized(self):
        result = evaluate_authorization_freshness(
            self.authz, current_digests(self.s0), OP
        )
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_material_change_invalidates_authorization(self):
        s1 = dict(self.s0)
        s1["k8s:service/api"] = "LoadBalancer"
        result = evaluate_authorization_freshness(
            self.authz, current_digests(s1), OP
        )
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.changed_subjects, ("k8s:service/api",))

    def test_unrelated_change_does_not_invalidate_authorization(self):
        s1 = dict(self.s0)
        s1["aws:tag/unrelated"] = "owner=security"
        result = evaluate_authorization_freshness(
            self.authz, current_digests(s1), OP
        )
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_missing_current_evidence_is_unknown(self):
        digests = current_digests(self.s0)
        del digests["aws:iam/api-role"]
        result = evaluate_authorization_freshness(self.authz, digests, OP)
        self.assertEqual(result.decision, Decision.INSUFFICIENT_EVIDENCE)
        self.assertEqual(result.missing_subjects, ("aws:iam/api-role",))

    def test_authorization_cannot_be_replayed_for_different_operation(self):
        different = digest_state("terraform-plan:sha256:plan-b")
        result = evaluate_authorization_freshness(
            self.authz, current_digests(self.s0), different
        )
        self.assertEqual(result.decision, Decision.DENY)


if __name__ == "__main__":
    unittest.main()
