# First end-to-end decision

This stage joins three independently derived evidence classes:

1. Kubernetes semantic identity path: Service -> workload -> ServiceAccount -> AWS role.
2. AWS network evidence.
3. Effective protected-data authorization evidence.

Invariant: an internet-reachable workload must not simultaneously have read access to the protected data resource.

The evaluator has four important behaviors:

- proven reachability + satisfied protected-data access => DENY;
- proven non-reachability + satisfied data access => ALLOW;
- proven reachability + denied data access => ALLOW;
- any material UNKNOWN => INSUFFICIENT_EVIDENCE.

This is the first complete decision pipeline in the lab, but the fixtures are still synthetic. It establishes decision semantics, not production validity.

The next falsification threshold is live evidence acquisition. We must replace fixture-produced AWS network and authorization evidence with captured outputs from authoritative AWS APIs in an isolated, low-cost test environment. Until then, no claim should be made that the system detects a real AWS/EKS unsafe transition.
