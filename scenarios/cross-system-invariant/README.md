# E1 — Cross-System Invariant

Invariant under test:

> A production workload must not be simultaneously internet reachable and authorized to read the protected data resource.

This scenario is intentionally cross-plane. Network exposure, workload identity, and data authorization are represented independently.

A useful counterexample must satisfy both conditions:

1. every local mutation is accepted by the baseline control responsible for that plane;
2. the composed resulting state violates the invariant.

If the baseline can express and enforce the invariant without an additional composition layer, this scenario falsifies rather than supports the thesis.
