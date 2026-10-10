# Projected Kubernetes service-account token — 2026-10-10

## Verified results

GitHub Actions [Kubernetes integration run 38066735151](https://github.com/EdwinJdevops/crossplane-authz-lab/actions/runs/38066735151), commit `f743ae1dd79445d40ba9ff624a658cb410b3e635`, completed successfully. The ephemeral kind cluster ran Job `cpal-token-check` with `serviceAccountName: cpal-collector`, `automountServiceAccountToken: false`, and an explicitly projected 600-second Kubernetes service-account token using the API-server default audience. The Job validated the API server TLS certificate using the cluster CA.

The Job log recorded:

```text
cpal-target: HTTP 200
cpal-target-sa: HTTP 200
other-pod: HTTP 403
pod-list: HTTP 403
Projected-token authentication and authorization controls passed
```

The same workflow passed the earlier eight `kubectl auth can-i --as` assertions and collected Pod and ServiceAccount identity through the runner's Kubernetes API client. The unit-test workflow [run 38066735135](https://github.com/EdwinJdevops/crossplane-authz-lab/actions/runs/38066735135) passed.

## Scope and limitations

The projected-token test proves that the Kubernetes API accepted the token presented by the in-cluster Job and enforced the tested resource-specific permissions. It does **not** authenticate any off-cluster evidence report, cryptographically bind an observation to a particular execution, verify AWS federation, prove the two-pass reads atomic, or establish a cross-system authorization invariant. The Python collector's `authenticated: false` field is correct for its *evidence provenance* contract and must not be changed based solely on this API authentication test. GitHub-hosted CI logs are operational evidence, not a signed, independently verified attestation.

## Next acceptance gate

Specify and test an independently verifiable collector attestation format with nonce, execution identifier, state/policy digests, collector identity, expiry, and replay rejection. Keep all authorization decisions fail-closed until a trusted verifier can establish those properties. Avoid deploying permanent or paid infrastructure for this gate.
