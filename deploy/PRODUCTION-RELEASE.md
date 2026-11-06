# CPAL staged release procedure — NO-GO until evidence approved

## Preconditions

- Production authorization remains disabled (`INDEPENDENT_COLLECTOR_ATTESTATION_REQUIRED`).
- An independent reviewer signs off on the AWS principal binding, Kubernetes source-of-truth and stale-state race model.
- Obtain an isolated staging AWS account or dedicated scoped role and a disposable Kubernetes cluster. Never run destructive probes against shared production resources.
- Record exact Git commit, image digest, dependency lock, SBOM, scanner output and reviewer identity in release evidence.

## Durability verification

1. Deploy `deploy/aws/challenge-store.yaml` using a dedicated verifier IAM role and an explicitly approved budget; record CloudFormation stack and table ARN.
2. Export `CPAL_DYNAMODB_CHALLENGE_TABLE` and run `python scripts/dynamodb_live_probe.py` with table-scoped IAM. Save logs and request IDs.
3. Start two verifier replicas with the same table; issue on replica A, consume on replica B, restart both and confirm replay remains rejected.
4. Block DynamoDB connectivity, assert all report submissions fail closed, restore connectivity and confirm fresh challenges work. Test throttling and lost-response retries.
5. Perform a point-in-time restore into a new table; prove restored consumed challenges cannot be replayed. Note: restoring an earlier state can resurrect unconsumed records; require a separate monotonic replay defense or refuse failover to stale snapshots.

## AWS–Kubernetes correctness

1. Use a dedicated, authorized staging role and cluster. In the verifier environment, install boto3 and set `CPAL_AWS_REGION`, `CPAL_AWS_ACCOUNT`, and `CPAL_AWS_ROLE_ARN` to the region, account, and exact expected **STS assumed-role session ARN**. Use a reviewed workload credential provider and separate scoped Kubernetes verifier credentials. The checked-in Kubernetes manifest explicitly enables `CPAL_KIND_FIXTURE=1` for disposable CI. Omit that variable from AWS-backed staging. The TLS verifier refuses startup with `CPAL_PRODUCTION_MODE=1`.
2. Record an exact execution ID, policy digest and AWS resource ARN; test the intended positive invariant without granting broader privileges.
3. Inject wrong AWS principal, resource, Pod UID, expired token, stale execution, changed policy, revoked RBAC, replay, concurrent mutations, and both control-plane outages.
4. Assert every negative case is denied; audit each request and remove disposable resources.

### Authenticated staging probe

The verifier performs TokenReview, checks the report digest, calls AWS STS for its own principal, and reads the configured Pod using its Kubernetes API credential. The submitted Pod UID, resource version, and execution ID must match. The verifier then atomically consumes the challenge. The STS principal check covers verifier identity. Pod credential provenance and effective AWS resource authorization require separate evidence.

Create a short-lived collector token file for the audience `cpal-collector-verification` and restrict access to the file. Obtain a current observation from the authorized staging cluster. The JSON observation contains `kind` (value `Pod`), `namespace`, `name`, `uid` and `resourceVersion`. Run from a host that can reach the staging TLS endpoint.

```sh
python scripts/staging_load_probe.py --url "$STAGING_ORIGIN" --ca "$STAGING_CA" \
  --token-file "$COLLECTOR_TOKEN_FILE" --observation-file "$POD_OBSERVATION_FILE" \
  --principal "$COLLECTOR_PRINCIPAL" --requests 24 --workers 4 --timeout 15
```

Expect denial for a forged UID, stale execution and self-reported verification flag. The same challenge must have exactly one successful concurrent submission, and a fresh challenge must still succeed. Use `--expect-denial` to assert the exact denial during each scoped fault. Use `STS_IDENTITY_MISMATCH` with a deliberately mismatched expected staging session, `STS_IDENTITY_UNAVAILABLE` with STS connectivity blocked, `INDEPENDENT_OBSERVATION_MISMATCH` with Pod-read RBAC revoked, `COLLECTOR_NOT_AUTHENTICATED` with TokenReview unavailable, and `CHALLENGE_STORE_UNAVAILABLE` with ledger access blocked. Restore access and repeat the healthy probe after each fault. Record commit, isolated environment, fault, result counts and latency without tokens or challenge nonces.

## Operational assurance

- Use immutable image digests, signed provenance, dependency lock and SBOM; enforce admission policies.
- Verify network policies on a CNI that actually enforces them, TLS key rotation, service-account token refresh and least privilege.
- Define latency and availability SLOs and dashboards for challenge issue/consume, denied decisions, TokenReview failures and DynamoDB throttling.
- Perform staged load and soak tests, pod termination, AZ disruption, alert drills and a documented rollback rehearsal.
- A release approver other than the implementer must review evidence. `python scripts/check_release_gates.py` must succeed using a reviewed evidence file; this is necessary but not sufficient if the evidence is false.

## Rollback

1. Disable all allow decisions first; maintain fail-closed behavior.
2. Stop new collector submissions and preserve redacted audit logs.
3. Roll back the verifier to a previously tested immutable digest, retaining the challenge table and IAM restrictions.
4. Do not restore an old challenge snapshot as a live replay authority without monotonic replay protection.
5. Revalidate TokenReview, Pod source-of-truth, DynamoDB replay rejection and cross-plane denials before reopening.
