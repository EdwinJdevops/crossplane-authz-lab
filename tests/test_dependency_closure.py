import json
import unittest
from pathlib import Path
from cpal.dependency import UnsupportedEvidence, derive_e1_dependency_closure

ROOT = Path(__file__).resolve().parents[1]
def load(path): return json.loads((ROOT / path).read_text())

class DependencyClosureTests(unittest.TestCase):
    def setUp(self):
        self.plan = load("fixtures/e1/terraform-plan.json")
        self.k8s = load("fixtures/e1/kubernetes.json")

    def test_derives_cross_plane_subjects_from_artifacts(self):
        result = derive_e1_dependency_closure(self.plan, self.k8s, "api")
        self.assertEqual(result.subjects, frozenset({
            "tf:aws_security_group.api","tf:aws_iam_role.api",
            "tf:aws_iam_role_policy.api_data","k8s:prod:Service:api",
            "k8s:prod:ServiceAccount:api",
            "aws-role:arn:aws:iam::111122223333:role/api-role"}))

    def test_unrelated_terraform_resource_is_not_in_closure(self):
        plan = json.loads(json.dumps(self.plan))
        plan["resource_changes"].append({"address":"aws_s3_bucket.logs","type":"aws_s3_bucket","change":{"actions":["no-op"],"after":{"bucket":"logs"}}})
        self.assertNotIn("tf:aws_s3_bucket.logs", derive_e1_dependency_closure(plan,self.k8s,"api").subjects)

    def test_missing_irsa_binding_fails_closed(self):
        objects=json.loads(json.dumps(self.k8s)); objects[1]["metadata"]["annotations"]={}
        with self.assertRaisesRegex(UnsupportedEvidence,"IRSA"):
            derive_e1_dependency_closure(self.plan,objects,"api")

    def test_missing_network_evidence_fails_closed(self):
        plan={**self.plan,"resource_changes":[r for r in self.plan["resource_changes"] if r["type"]!="aws_security_group"]}
        with self.assertRaisesRegex(UnsupportedEvidence,"network"):
            derive_e1_dependency_closure(plan,self.k8s,"api")

if __name__=="__main__": unittest.main()
