import json, unittest
from pathlib import Path
from cpal.k8s_graph import EdgeStatus, derive_kubernetes_identity_graph
ROOT=Path(__file__).resolve().parents[1]
def fixture(): return json.loads((ROOT/"fixtures/e1/kubernetes-graph.json").read_text())

class KubernetesGraphTests(unittest.TestCase):
    def test_proves_service_workload_identity_role_chain(self):
        r=derive_kubernetes_identity_graph(fixture(),"api","prod")
        self.assertEqual(r.unknowns,())
        triples={(e.relation,e.target,e.status) for e in r.edges}
        self.assertIn(("selects","k8s:prod:Deployment:api",EdgeStatus.PROVEN),triples)
        self.assertIn(("uses_identity","k8s:prod:ServiceAccount:api",EdgeStatus.PROVEN),triples)
        self.assertIn(("assumes_role","aws-role:arn:aws:iam::111122223333:role/api-role",EdgeStatus.PROVEN),triples)

    def test_selector_mismatch_is_unknown_not_invented_edge(self):
        o=fixture(); o[1]["spec"]["template"]["metadata"]["labels"]["app"]="other"
        r=derive_kubernetes_identity_graph(o,"api","prod")
        self.assertTrue(any("matches no supported workload" in x for x in r.unknowns))
        self.assertFalse(any(e.relation=="selects" for e in r.edges))

    def test_missing_service_account_is_unknown(self):
        o=fixture(); o.pop()
        r=derive_kubernetes_identity_graph(o,"api","prod")
        self.assertTrue(any("ServiceAccount" in x for x in r.unknowns))
        self.assertFalse(any(e.relation=="assumes_role" for e in r.edges))

    def test_missing_irsa_annotation_is_unknown(self):
        o=fixture(); o[2]["metadata"]["annotations"]={}
        r=derive_kubernetes_identity_graph(o,"api","prod")
        self.assertTrue(any("IRSA" in x for x in r.unknowns))
        self.assertFalse(any(e.relation=="assumes_role" for e in r.edges))

if __name__=="__main__": unittest.main()
