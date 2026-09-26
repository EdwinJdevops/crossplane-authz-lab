# Experiment Design

## Method

Every experiment has three implementations:

1. **Fixture** — deterministic representation of the proposed and current states.
2. **Baseline** — the strongest existing controls relevant to the scenario.
3. **Candidate** — state/evidence-bound evaluation.

The candidate only passes if it catches a meaningful unsafe transition missed by the baseline without misclassifying equivalent safe transitions.

## E1 — Cross-system invariant

Target invariant:

> A production workload must not be simultaneously internet reachable and authorized to read the protected data resource.

The experiment separates network exposure, workload identity, and data authorization so that each control plane can accept a locally valid state while the composition violates the invariant.

We will first model this without AWS spend. A later live experiment is permitted only after the fixture demonstrates a baseline gap.

## E2 — Stale authorization

Authorize transition T against state S0 and evidence E0.

Mutate a dependency in S0 to produce S1 before execution.

Required property:

An authorization whose material assumptions changed must not remain valid.

The experiment must distinguish relevant from irrelevant state changes; invalidating every authorization on every state change is considered failure.

## E3 — Delegated authority

Originating principal cannot perform operation X.

A delegated tool technically can perform X.

Required property:

Delegation must not increase effective authority unless a separately authenticated and auditable privilege transition explicitly permits it.

## E4 — Unknown state

A consequential property is unknown before apply/runtime.

Required behavior is INSUFFICIENT_EVIDENCE or BOUNDED_EXECUTION, never implicit ALLOW.

## Metrics

- unsafe transitions admitted;
- safe transitions denied;
- unknowns incorrectly treated as known;
- stale authorizations accepted;
- unauthorized authority amplification;
- evaluation latency;
- number of required external observations;
- reauthorization frequency.

## Stop conditions

Stop if:
- baseline controls enforce the invariant equally well;
- candidate relies on unverifiable model judgment;
- candidate cannot identify the evidence on which authorization depends;
- safe operations require pervasive manual bypass.
