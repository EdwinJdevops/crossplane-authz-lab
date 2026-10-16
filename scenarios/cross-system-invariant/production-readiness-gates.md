# Production admission: NO-GO until independently verified

Last assessment: 2026-10-16. This is a security research prototype, not an approved production authorization service.

## Verified in disposable CI

- Separate Kubernetes collector Job and verifier Deployment with a cluster-internal HTTPS Service.
- Disposable test CA, TLS verification, projected ServiceAccount credentials, and live Kubernetes TokenReview.
- Verifier-issued challenge, digest binding, one-time consumption, invalid-token and replay rejection in integration tests.
- Scoped read-only Pod RBAC and separate verifier TokenReview privilege.

## Blocking gates (not verified)

1. **Observation provenance:** bearer-token possession authenticates a principal, not the integrity or origin of arbitrary report bytes. A compromised collector can fabricate observations. Require an independently trusted observation path or attestable collection with a documented threat model; demonstrate forged-observation rejection before any allow decision.
2. **Cross-system invariant:** design and run positive and adversarial AWS–Kubernetes tests against explicitly scoped disposable resources. Validate stale state, wrong AWS principal, wrong Kubernetes UID, privilege escalation, revoked/expired token, replay, race, partial outage and cleanup. Existing S3 tests are not end-to-end proof.
3. **Runtime security:** pin images by digest, establish supply-chain provenance/SBOM, vulnerability scans, admission policy, resource limits, NetworkPolicy, TLS key lifecycle, rotation, storage durability, backup/recovery and audit trails. CI fixture secrets and ConfigMaps are not production secret distribution.
4. **Availability:** verifier currently stores challenges in a pod-local SQLite file and reads a projected verifier token only at startup. Pod restart loses pending challenges; token expiration will eventually break TokenReview. Implement secure credential refresh and transactional durable state with concurrency and outage testing.
5. **Adversarial assurance:** independent security review, threat model, fuzzing, negative test coverage, disaster recovery exercises and a documented rollback.
6. **Operational release:** staging soak, monitoring, alerting, SLOs, ownership, incident runbooks, change approval and rollback rehearsals.

## Release decision

`NO-GO` for production authorization. The existing `INDEPENDENT_COLLECTOR_ATTESTATION_REQUIRED` fail-closed decision must remain until gates are satisfied with reproducible evidence. Do not claim production readiness based on green CI alone.

No production AWS resources are required for the current tests; continue to use disposable kind and scoped ephemeral infrastructure.
