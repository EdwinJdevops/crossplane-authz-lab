# Collector-to-verifier reporting transport: acceptance gates

## Verified today

- A loopback-only HTTP prototype exercises Kubernetes TokenReview, persisted verifier-issued challenge validation, and replay rejection in ephemeral kind CI.
- The prototype is explicitly **not** a production endpoint. The live CI test uses a runner-generated collector token and runner-generated report, not a separately deployed collector workload.
- HTTP requests have bounded body sizes and read timeouts. These do not provide encryption, authentication of report origin, or availability guarantees.

## Required before any cross-pod deployment

1. Deploy separate collector and verifier workloads in disposable kind. The verifier must not expose an unauthenticated HTTP Service to other pods or networks.
2. Use an authenticated encrypted transport (e.g. TLS with independently provisioned server identity) with certificate verification on the collector side. Do not use `verify=False`, self-signed certificates without a trusted anchor, or plain HTTP between pods.
3. Keep verifier Kubernetes API credentials, trust roots and SQLite challenge database inaccessible to collector workloads. Apply least-privilege ServiceAccounts and restrictive filesystem permissions.
4. Verifier issues random, expiring challenges and records the expected principal and execution ID. The collector submits the exact report bytes and challenge nonce over the protected channel, using its own projected short-lived Kubernetes token.
5. Verifier performs TokenReview directly over Kubernetes API TLS and checks audience, username and ServiceAccount UID; reject missing or ambiguous identity.
6. Challenge is atomically consumed only after authenticated identity, report digest and execution binding checks pass. Reject replay, wrong principal, forged nonce, wrong execution, expired challenge and storage outage.
7. Exercise negative network tests: connection to wrong server certificate, unauthenticated requests, invalid token, oversized/truncated requests, concurrent replay, API timeout and restart persistence.
8. Do not accept reports as cross-system authorization-grade until AWS evidence provenance, Kubernetes observation freshness, and the full cross-system invariant are independently verified.

## Explicit limitations

- Kubernetes TokenReview authenticates a bearer token; it does **not** prove that the collector process generated the submitted report. A stolen bearer token remains usable until expiry or revocation. Stronger proof-of-possession or an independently trusted collection channel is required if that threat is in scope.
- SQLite is appropriate for one verifier process using a shared local database file; multi-replica deployment requires a transactional shared datastore and operational recovery design.
- The current HTTP server must remain loopback-only. Do not expose it via Service, Ingress, public port or port-forward.
- No production mutations are authorized by this work.
