# Kubernetes RBAC and API collection — 2026-10-10

## Verified execution

GitHub Actions [run 38057360692](https://github.com/EdwinJdevops/crossplane-authz-lab/actions/runs/38057360692) provisioned an ephemeral kind cluster, applied the scoped `cpal-experiment` fixtures and RBAC, and executed the collector against the live Kubernetes API.

The two permitted operations returned `yes` (exit 0): `get pods/cpal-target` and `get serviceaccounts/cpal-target-sa` as `system:serviceaccount:cpal-experiment:cpal-collector`.

The six denied operations returned `no` (exit 1): reading another Pod, reading another ServiceAccount, listing Pods, watching Pods, deleting the named Pod, and updating the named ServiceAccount. The test script explicitly accepts the nonzero status of a denied authorization check while checking the exact response.

The API collector reported Pod UID `f604a145-3dd8-40ed-b1ac-ab7b42f195d7` with resourceVersion `477`, and ServiceAccount UID `37fc3a77-66a3-4e0a-93de-21d725332a1c` with resourceVersion `466`. The output set `authenticated: false` by design. The cluster was disposable and was cleaned up by the GitHub action.

## Evidence limitations

This file is a human-readable record pointing to hosted job logs, not a signed attestation. Kubernetes `kubectl auth can-i --as` uses administrator impersonation in this CI test; it is **not** proof of a collector workload successfully authenticating with a projected ServiceAccount token. The collector uses the runner's kubeconfig and cluster-admin-level test identity. The two-pass read does not establish an atomic snapshot or protect against post-read mutation. The experiment does not demonstrate Kubernetes-to-AWS federation, network policy behavior, or a cross-control-plane invariant.

## Next gate

Run the collector using a projected, narrowly scoped Kubernetes ServiceAccount token inside the disposable cluster; verify successful reads and denied unauthorized operations using that actual token, not only administrator impersonation. Bind execution identity and snapshot state to an independently verifiable evidence channel before consuming these results for decisions.
