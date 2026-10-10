# Collector identity: trust-boundary decision

## Current decision

No evidence report may authorize a cross-system mutation. The HMAC verifier validates shared-secret possession, execution binding, expiry and replay for a local prototype. It does not prove the report originated from the Kubernetes service account or an independently authenticated AWS principal. A caller-provided `CollectorIdentity(authenticated=True)` is not a trusted authentication result; the evidence gate therefore returns `INDEPENDENT_COLLECTOR_ATTESTATION_REQUIRED` even after local MAC validation.

## Next minimal integration (disposable kind, no AWS charges)

1. Run a Kubernetes collector with an explicitly projected short-lived service-account token, `automountServiceAccountToken: false`, pinned API audience and namespace-scoped RBAC. The prior kind test established API authentication and RBAC only.
2. Implement a separate trusted verifier that performs Kubernetes `TokenReview` with the exact expected audience and validates `status.authenticated`, service-account username, namespace, UID and token lifetime where available. The verifier must not accept a username/boolean provided by the collector. Limit TokenReview permission to the verifier service account, never the collector.
3. Bind the authenticated transport session to a single report and a verifier-issued, single-use nonce. TokenReview by itself authenticates a bearer token, not the bytes of a report; possession of a stolen token is a risk. Use TLS for transport, restrict token exposure and logs, and require a digest of the exact received report in the attestation envelope.
4. Use a durable, atomic nonce store in the verifier. SQLite is acceptable for a single-host experiment, not for independent distributed verifier replicas. Do not store service-account bearer tokens in evidence or CI logs.
5. Adversarial tests: invalid audience, wrong namespace/SA/UID, expired token, token swap, mismatched execution/policy/state/report digest, forged report, duplicate nonce and storage outage. Verify the result remains insufficient evidence on any failure.
6. Separately authenticate AWS evidence with its own trust chain and explicit execution binding. Kubernetes TokenReview cannot establish AWS identity or a cross-system invariant.

## Acceptance criteria

- Identity verification occurs in a distinct trusted verifier, not in a caller-supplied dataclass.
- The verifier enforces audience, issuer/trust root, namespace, service-account UID, nonce, time window and exact evidence digest.
- The test demonstrates authorized and rejected paths against a live disposable kind API, including a replay attempt.
- Any missing verification or inconsistent read yields `INSUFFICIENT_EVIDENCE`; no automatic remediation is enabled.

## Non-goals

No permanent cluster, paid AWS resources, generic PKI platform, or claim that a successful TokenReview proves atomic Kubernetes state snapshots.
