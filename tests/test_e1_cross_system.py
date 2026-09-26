import unittest

from cpal.baseline import evaluate_local_controls
from cpal.candidate import evaluate_cross_system_invariant
from cpal.model import Decision, WorkloadState


class CrossSystemInvariantTests(unittest.TestCase):
    def test_safe_public_workload_without_protected_data(self):
        state = WorkloadState("api", True, frozenset({"public-assets"}))
        self.assertTrue(all(d.decision is Decision.ALLOW for d in evaluate_local_controls(state)))
        self.assertEqual(evaluate_cross_system_invariant(state).decision, Decision.ALLOW)

    def test_safe_private_workload_with_protected_data(self):
        state = WorkloadState("worker", False, frozenset({"protected-s3"}))
        self.assertTrue(all(d.decision is Decision.ALLOW for d in evaluate_local_controls(state)))
        self.assertEqual(evaluate_cross_system_invariant(state).decision, Decision.ALLOW)

    def test_unsafe_composition_is_missed_by_local_controls(self):
        state = WorkloadState("api", True, frozenset({"protected-s3"}))
        self.assertTrue(all(d.decision is Decision.ALLOW for d in evaluate_local_controls(state)))
        result = evaluate_cross_system_invariant(state)
        self.assertEqual(result.decision, Decision.DENY)

    def test_unknown_network_is_not_silently_allowed(self):
        state = WorkloadState("api", None, frozenset({"protected-s3"}))
        self.assertEqual(
            evaluate_cross_system_invariant(state).decision,
            Decision.INSUFFICIENT_EVIDENCE,
        )

    def test_unknown_data_authorization_is_not_silently_allowed(self):
        state = WorkloadState("api", True, None)
        self.assertEqual(
            evaluate_cross_system_invariant(state).decision,
            Decision.INSUFFICIENT_EVIDENCE,
        )


if __name__ == "__main__":
    unittest.main()
