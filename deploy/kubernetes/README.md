# Kubernetes collector integration gate

This configuration has **not** been deployed to a live cluster. It is an RBAC boundary for a future disposable experiment, not evidence of working Kubernetes access.

1. Use a disposable local Kubernetes cluster (for example kind) or an explicitly authorized test cluster. Confirm the active kubeconfig context before applying anything. Do not run this against a production context.
2. Review `collector-rbac.yaml`. It creates namespace `cpal-experiment`, service account `cpal-collector` (automatic token mounting disabled), and a namespaced Role that grants only `get` on Pod `cpal-target` and ServiceAccount `cpal-target-sa`.
3. Apply the manifest: `kubectl apply -f deploy/kubernetes/collector-rbac.yaml`. Create the target Pod and ServiceAccount separately in the test namespace. Do not deploy a collector workload until a narrowly scoped, explicitly mounted projected service-account token is configured.
4. Check authorization using impersonation with an administrator test identity: `kubectl auth can-i get pods/cpal-target -n cpal-experiment --as=system:serviceaccount:cpal-experiment:cpal-collector`; confirm `yes`. Check `kubectl auth can-i list pods -n cpal-experiment --as=system:serviceaccount:cpal-experiment:cpal-collector`; confirm `no`. Confirm `get` for other Pod names and write verbs are denied.
5. From an authorized test kubeconfig, install the Python `kubernetes` package and run `PYTHONPATH=src python scripts/collect_kubernetes_identity.py --namespace cpal-experiment --pod cpal-target`. This uses configured TLS and credentials, reads Pod and ServiceAccount twice, and prints an observation with `authenticated: false`.

**Security limits:** Kubernetes API TLS and credential authentication establish the server/client channel under the kubeconfig trust configuration, but this script does not attest its execution environment or bind the observation to an immutable execution ID. Two reads are not an atomic snapshot. Kubernetes resourceVersion is opaque. RBAC alone does not prove AWS role assumption or network policy behavior. No automatic ALLOW decisions should consume these outputs.
