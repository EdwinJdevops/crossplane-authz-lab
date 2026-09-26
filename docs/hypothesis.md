# Hypothesis

## Claim under test

Local authorization decisions across heterogeneous control planes are not necessarily compositional.

A multi-step infrastructure operation can be locally admissible at each boundary while the resulting cross-system state violates an invariant that no individual control plane owns.

We are testing whether a state/evidence-bound authorization layer can detect such transitions without claiming knowledge it does not possess.

## Non-claims

We do not claim:
- agent governance is unsolved;
- IAM, OPA, admission control, provenance, or deployment gates are missing;
- all autonomous infrastructure operations exhibit this failure;
- an LLM can certify safety;
- cross-system assurance is commercially validated.

## Decision model

The evaluator must return one of:

- ALLOW
- DENY
- INSUFFICIENT_EVIDENCE
- BOUNDED_EXECUTION

ALLOW means all declared invariants relevant to the proposed transition are supported by fresh evidence.
DENY means available evidence proves a declared invariant would be violated.
INSUFFICIENT_EVIDENCE means a required property cannot be established.
BOUNDED_EXECUTION means evidence can only be obtained after a constrained transition whose exposure is explicitly bounded.

## Kill criterion

If existing controls, correctly composed, enforce the same cross-system properties without an additional state/evidence binding mechanism, stop.
