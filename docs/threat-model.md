# Threat Model

## Protected property

Execution authority must not silently exceed the consequence envelope evaluated and authorized for the originating operation.

## Actors

- human initiator;
- coding/operations agent;
- delegated agent or MCP tool;
- GitHub workflow;
- Terraform;
- AWS control plane;
- Kubernetes admission/runtime;
- independent concurrent actor.

No actor is assumed malicious in the initial experiments. Accidental unsafe composition is sufficient.

## Failure classes

### Cross-system composition

Two or more locally allowed changes jointly violate a global invariant.

### Authorization staleness

Evidence is valid at authorization time, relevant state changes, and execution proceeds using an authorization whose assumptions no longer hold.

### Delegation amplification

A child/delegated execution path can exercise authority unavailable to the originating principal without an explicit authorized privilege transition.

### Epistemic incompleteness

A consequential property is unknown until apply/runtime. The system incorrectly converts UNKNOWN into ALLOW.

## Out of scope for Phase 0

- prompt-injection detection;
- model alignment;
- malware;
- employee scoring;
- generic AI observability;
- production deployment;
- claims of complete safety.

## Root-of-trust rule

Only deterministic or independently verifiable evidence can authorize a transition. Model-generated assertions are untrusted input.
