# Dependency-closure experiment

The stale-authorization fixture previously hand-authored the state subjects on which authorization depended. That is not acceptable as a final mechanism.

This experiment begins replacing that assumption with deterministic derivation from infrastructure artifacts.

## Current recognized evidence

The parser currently recognizes only the narrow E1 path: Terraform AWS security-group resources as network evidence; Terraform AWS IAM role/policy resources as data-authorization evidence; Kubernetes Service as exposure evidence; and a Kubernetes ServiceAccount IRSA annotation as the identity bridge from Kubernetes to AWS.

## Fail-closed rule

If a required semantic bridge cannot be established, derivation raises an unsupported-evidence result. It does not guess. A false claim of completeness is worse than returning UNKNOWN.

## Important limitation

This is not yet a general dependency graph. It does not prove which workload uses the ServiceAccount, whether a Service selects that workload, whether the AWS security group governs the serving path, or whether IAM access survives SCPs, permission boundaries, session policies, resource policies, KMS policy and explicit denies. It also does not establish actual reachability through routes, NACLs, load balancers, gateways or firewalls.

Those are the next falsification boundary. Until authoritative evidence establishes those edges, the closure must not be called complete.
