# E1 Hostile Baseline Analysis

## Result

The original E1 toy counterexample does **not** establish a missing authorization primitive.

If a central policy gate is supplied both facts:

- whether the workload is internet reachable; and
- whether the workload can read the protected data resource,

then an ordinary policy engine can directly reject their forbidden conjunction.

This is a falsification result and is retained deliberately.

## What existing controls establish

### OPA / Terraform

OPA evaluates Terraform plan JSON and can incorporate data other than the plan. Therefore, when all facts required by the invariant are represented in the policy input, the invariant is expressible without a new authorization mechanism.

The documented limitation is evidence availability: Terraform plan JSON can contain unknown values and runtime-dependent information may not exist at plan time.

### AWS IAM Access Analyzer

IAM Access Analyzer custom policy checks provide strong logical reasoning over IAM policies, including no-new-access and specified-access checks. AWS documents that custom policy checks are environment-agnostic: they reason from the input policies and do not automatically compose arbitrary external environment state such as Kubernetes exposure.

This makes Access Analyzer valuable evidence for the IAM side of E1, not an end-to-end evaluator of the proposed network + workload + data invariant.

### Kubernetes admission

ValidatingAdmissionPolicy evaluates matching Kubernetes admission requests and optional Kubernetes parameter resources. It is an enforcement point for Kubernetes objects. It is not, by itself, a model of AWS IAM reachability.

A validating webhook could call an external service, so Kubernetes does not make cross-plane evaluation impossible. That changes the engineering question from policy expressiveness to evidence acquisition, freshness, binding, and failure semantics.

## Corrected E1 hypothesis

E1 survives only if we can demonstrate at least one of the following under realistic control-plane semantics:

1. a required fact is not available to the central gate at authorization time;
2. the fact is available but cannot be bound to the exact operation being authorized;
3. relevant state changes after evidence collection and before execution;
4. delegated execution crosses an enforcement boundary without preserving the originating authorization;
5. obtaining complete evidence requires execution, so the correct result is UNKNOWN or bounded execution.

If none occurs in a realistic implementation, E1 is falsified.

## Next fixture

Do not add another synthetic policy rule.

The next fixture must model evidence provenance and freshness separately from workload state:

- network observation with subject, digest and observation time;
- IAM/access observation with subject, digest and observation time;
- proposed operation digest;
- authorization binding to those exact observations.

The test then mutates one material dependency after authorization. That joins E1 to E2 and tests the actual remaining claim: composition under changing heterogeneous state.
