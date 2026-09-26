# E2 — Stale Authorization

An operation is authorized against S0.

Before execution, a concurrent actor changes a material dependency to produce S1.

The candidate must invalidate authorization only when the changed state participates in the authorization's evidence/dependency closure.

Global invalidation on every state mutation is not considered a successful design.
