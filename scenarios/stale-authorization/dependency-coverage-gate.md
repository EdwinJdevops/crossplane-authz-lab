# Dependency coverage gate: scope and limitations

The initial freshness evaluator compares only evidence subjects already bound to an authorization. An omitted material dependency therefore creates a fail-open risk. `evaluate_with_coverage` adds an explicit required-subject set and returns `INSUFFICIENT_EVIDENCE` if required subjects are unbound, unknown dependencies exist, or closure has not been declared complete.

**Trust boundary:** `DependencyCoverage.complete=True` is supplied by a caller. It is not a proof of semantic completeness. An adversarial or buggy caller can omit a dependency from both `required_subjects` and the authorization, then claim completion. The gate alone does not prevent this. Do not use it as a production authorization boundary.

## Next experiment

1. Define a narrow supported workload-to-service-to-service-account-to-role path and enumerate the evidence required for that path.
2. Generate coverage from verified source-specific adapters, not from a user-provided `complete=True` flag.
3. Introduce a missing selector, unknown identity, unmodeled IAM policy, or unsupported AWS network path; require `INSUFFICIENT_EVIDENCE`.
4. Change one verified material dependency after authorization; require invalidation. Change an unrelated subject; require no invalidation.
5. Compare against an equally informed OPA/standard-policy baseline. If the baseline produces equivalent decisions with comparable operational cost, the gate is not a novel contribution.

No claim of general dependency closure, real-world effective S3 access, or cross-system safety follows from these tests.
