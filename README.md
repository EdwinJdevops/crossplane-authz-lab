# Cross-Plane Authorization Lab

This repository is a falsification lab for one systems hypothesis:

> Can heterogeneous infrastructure control planes preserve a cross-system safety invariant throughout an autonomous multi-step operation when authority is delegated, evidence becomes stale, or relevant state is unknown?

This is not an AI-governance dashboard, risk-score product, Terraform scanner, or claim that an LLM can determine whether infrastructure is safe.

## Research boundary

The first phase tests four failure classes:

1. cross-system invariant violation;
2. stale authorization;
3. delegated-authority amplification;
4. unknown-state handling.

The baseline is the strongest composition we can construct from existing controls: GitHub workflow/deployment controls, Terraform plan/state semantics, AWS IAM and Access Analyzer where applicable, OPA policy, and Kubernetes admission/policy controls.

The experimental mechanism is allowed to succeed only by using externally verifiable evidence. An LLM may not be a root of trust.

## Falsification

Kill the thesis if correctly configured existing controls preserve the same invariants with equivalent or better correctness and acceptable operator cost.

Also kill it if the experimental mechanism:
- collapses to a static risk score;
- cannot distinguish DENY from INSUFFICIENT_EVIDENCE;
- silently treats unknown state as safe;
- cannot bind authorization to the exact operation/evidence/state it evaluated;
- requires impractical false-positive or reauthorization rates.

No production resources are provisioned in Phase 0.
