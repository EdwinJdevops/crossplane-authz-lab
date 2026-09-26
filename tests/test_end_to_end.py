import json, unittest
from pathlib import Path
from cpal.access_requirements import RequirementStatus as S, s3_get_object_contract
from cpal.aws_evidence import Assurance, AwsEvidenceResult
from cpal.end_to_end import evaluate_protected_data_invariant
from cpal.k8s_graph import derive_kubernetes_identity_graph
from cpal.model import Decision
ROOT=Path(__file__).resolve().parents[1]
def graph():
    objs=json.loads((ROOT/"fixtures/e1/kubernetes-graph.json").read_text())
    return derive_kubernetes_identity_graph(objs,"api","prod")
def net(a):
    return AwsEvidenceResult(a,"internet","reaches api","fixture","reachability-analyzer")
def access(v):
    return s3_get_object_contract(identity=v,boundary=v,scp=v,bucket_policy=v,rcp=v,endpoint_policy=v)

class EndToEndTests(unittest.TestCase):
    def test_forbidden_composition_is_denied(self):
        self.assertEqual(evaluate_protected_data_invariant(graph(),net(Assurance.PROVEN),access(S.SATISFIED)).decision,Decision.DENY)
    def test_private_workload_with_data_access_is_allowed(self):
        self.assertEqual(evaluate_protected_data_invariant(graph(),net(Assurance.DENIED),access(S.SATISFIED)).decision,Decision.ALLOW)
    def test_public_workload_without_data_access_is_allowed(self):
        self.assertEqual(evaluate_protected_data_invariant(graph(),net(Assurance.PROVEN),access(S.DENIED)).decision,Decision.ALLOW)
    def test_unknown_data_access_never_becomes_allow(self):
        self.assertEqual(evaluate_protected_data_invariant(graph(),net(Assurance.PROVEN),access(S.UNKNOWN)).decision,Decision.INSUFFICIENT_EVIDENCE)
    def test_unknown_network_never_becomes_allow(self):
        self.assertEqual(evaluate_protected_data_invariant(graph(),net(Assurance.UNKNOWN),access(S.SATISFIED)).decision,Decision.INSUFFICIENT_EVIDENCE)

if __name__=="__main__": unittest.main()
