import unittest
from cpal.aws_evidence import Assurance, iam_role_s3_evidence, reachability_evidence

ROLE="arn:aws:iam::111122223333:role/api-role"
OBJ="arn:aws:s3:::protected-data/customer.csv"

class AwsEvidenceTests(unittest.TestCase):
    def test_iam_allow_is_not_overclaimed_as_proof(self):
        raw={"EvaluationResults":[{"EvalActionName":"s3:GetObject","EvalResourceName":OBJ,"EvalDecision":"allowed"}]}
        self.assertEqual(iam_role_s3_evidence(raw,ROLE,OBJ).assurance,Assurance.UNKNOWN)

    def test_iam_explicit_deny_is_negative_evidence(self):
        raw={"EvaluationResults":[{"EvalActionName":"s3:GetObject","EvalResourceName":OBJ,"EvalDecision":"explicitDeny"}]}
        self.assertEqual(iam_role_s3_evidence(raw,ROLE,OBJ).assurance,Assurance.DENIED)

    def test_network_path_found_is_proven_reachability(self):
        raw={"Status":"succeeded","NetworkPathFound":True}
        self.assertEqual(reachability_evidence(raw,"igw-1","eni-1").assurance,Assurance.PROVEN)

    def test_incomplete_network_analysis_is_unknown(self):
        raw={"Status":"running"}
        self.assertEqual(reachability_evidence(raw,"igw-1","eni-1").assurance,Assurance.UNKNOWN)

if __name__=="__main__": unittest.main()
