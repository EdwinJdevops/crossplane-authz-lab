# Live TokenReview evidence — 2026-10-10

GitHub Actions [Kubernetes integration run 38087089692](https://github.com/EdwinJdevops/crossplane-authz-lab/actions/runs/38087089692) completed successfully against an ephemeral kind API server. The workflow created a short-lived service-account token for `cpal-collector` with audience `cpal-collector-verification`, transferred it via a temporary namespaced Kubernetes Secret into a dedicated verifier Job, and deleted the Secret after success. The verifier used its own projected API-audience token to create `authentication.k8s.io/v1` TokenReview requests. Its separate ClusterRole allows TokenReview creation but not Secret reads.

Verified Job logs:

```text
collector identity and audience: authenticated
wrong audience: rejected
invalid token: rejected
```

The workflow's previous stages also asserted the verifier/collector RBAC separation. Unit-test [run 38087089614](https://github.com/EdwinJdevops/crossplane-authz-lab/actions/runs/38087089614) passed.

## Security limitations

This proves live TokenReview verification of a Kubernetes-issued collector token and negative audience/invalid-token cases. It does **not** prove that a particular evidence report was produced by the collector: the CI harness requested the collector token and provisioned it to the verifier via a temporary Secret. This is an authentication API integration test, not an end-to-end collector-to-verifier authenticated reporting channel. The Secret-based test fixture is not a production token transport design. TokenReview does not provide proof-of-possession or report integrity. Kubernetes API authorization is not AWS identity, atomic snapshot consistency, or cross-system safety. No authorization-grade decision is enabled.

## Next gate

Build a collector-originated authenticated report exchange using TLS, a verifier-generated single-use challenge, exact report digest binding, and a verified token identity. The verifier must enforce replay and report freshness atomically and reject missing trust anchors, altered reports, wrong identity, and stale execution state. No permanent infrastructure or AWS changes.
