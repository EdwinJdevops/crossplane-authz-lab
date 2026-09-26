# Kubernetes semantic-edge derivation

This stage replaces co-existence assumptions with evidence-backed edges.

The evaluator now proves only three narrow relationships from Kubernetes object semantics:

1. Service -> workload, when the Service selector matches the workload pod-template labels.
2. workload -> ServiceAccount, from pod-template serviceAccountName.
3. ServiceAccount -> AWS role, from the EKS IRSA role annotation.

A missing selector, selector mismatch, missing ServiceAccount object, or absent IRSA annotation produces UNKNOWN. No edge is synthesized.

This is still not proof that traffic from the internet reaches the selected Pods. Service type alone is insufficient for that claim. Nor does an IRSA annotation prove effective AWS permissions. Those require authoritative AWS-side evidence and remain outside this graph until integrated.

The next cross-plane join is therefore explicit: Kubernetes can establish which AWS role a selected workload intends to assume; AWS evidence must independently establish the role's effective access and network path.
