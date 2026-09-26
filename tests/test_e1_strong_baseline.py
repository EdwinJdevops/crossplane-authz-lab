import unittest

from cpal.model import Decision, WorkloadState
from cpal.strong_baseline import evaluate_central_policy


class StrongBaselineTests(unittest.TestCase):
    def test_complete_evidence_falsifies_e1_novelty(self):
        unsafe = WorkloadState("api", True, frozenset({"protected-s3"}))
        self.assertEqual(evaluate_central_policy(unsafe).decision, Decision.DENY)

    def test_safe_compositions_are_not_blocked(self):
        public = WorkloadState("api", True, frozenset({"public-assets"}))
        private = WorkloadState("worker", False, frozenset({"protected-s3"}))
        self.assertEqual(evaluate_central_policy(public).decision, Decision.ALLOW)
        self.assertEqual(evaluate_central_policy(private).decision, Decision.ALLOW)

    def test_missing_cross_plane_evidence_is_not_treated_as_safe(self):
        missing_network = WorkloadState("api", None, frozenset({"protected-s3"}))
        missing_access = WorkloadState("api", True, None)
        self.assertEqual(
            evaluate_central_policy(missing_network).decision,
            Decision.INSUFFICIENT_EVIDENCE,
        )
        self.assertEqual(
            evaluate_central_policy(missing_access).decision,
            Decision.INSUFFICIENT_EVIDENCE,
        )


if __name__ == "__main__":
    unittest.main()
