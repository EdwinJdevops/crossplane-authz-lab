# E2 — State-bound authorization fixture

## Property under test

An authorization is valid only for the exact operation and the material state observations on which its decision depended.

This fixture intentionally does **not** invalidate authorization when unrelated state changes. Global invalidation would be safe but operationally useless and would not demonstrate dependency-aware authorization.

## Binding

The authorization binds:

- proposed operation digest;
- AWS network subject digest;
- AWS IAM/workload-identity subject digest;
- Kubernetes service subject digest.

A tag outside that dependency closure is deliberately excluded.

## Required outcomes

| Condition | Decision |
| --- | --- |
| exact operation + unchanged bound state | ALLOW |
| exact operation + changed bound subject | DENY |
| exact operation + missing bound observation | INSUFFICIENT_EVIDENCE |
| different operation | DENY |
| unrelated state changed | ALLOW |

## What this does not prove

This deterministic fixture proves that selective invalidation is implementable once the dependency closure is known.

It does **not** prove that deriving the correct dependency closure from Terraform, AWS and Kubernetes is solved. That derivation is the hard next step and must not be hidden behind hand-authored subject lists.
