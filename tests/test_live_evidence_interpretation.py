import unittest
from cpal.aws_evidence import Assurance, iam_role_s3_evidence

ROLE = 'arn:aws:iam::123456789012:role/cpal-fixture'
OBJECT = 'arn:aws:s3:::cpal-fixture/fixture/harmless.txt'

class LiveEvidenceInterpretationTests(unittest.TestCase):
    def test_real_world_allowed_simulation_is_not_effective_access_proof(self):
        response = {'EvaluationResults': [{'EvalActionName': 's3:GetObject', 'EvalResourceName': OBJECT, 'EvalDecision': 'allowed', 'MatchedStatements': [{}]}]}
        evidence = iam_role_s3_evidence(response, ROLE, OBJECT)
        self.assertEqual(evidence.assurance, Assurance.UNKNOWN)

    def test_real_world_implicit_deny_for_delete_cannot_answer_get_claim(self):
        response = {'EvaluationResults': [{'EvalActionName': 's3:DeleteObject', 'EvalResourceName': OBJECT, 'EvalDecision': 'implicitDeny', 'MatchedStatements': []}]}
        evidence = iam_role_s3_evidence(response, ROLE, OBJECT)
        self.assertEqual(evidence.assurance, Assurance.UNKNOWN)

    def test_mismatched_object_does_not_transfer_authorization(self):
        response = {'EvaluationResults': [{'EvalActionName': 's3:GetObject', 'EvalResourceName': 'arn:aws:s3:::other-bucket/x', 'EvalDecision': 'allowed'}]}
        self.assertEqual(iam_role_s3_evidence(response, ROLE, OBJECT).assurance, Assurance.UNKNOWN)

if __name__ == '__main__':
    unittest.main()
