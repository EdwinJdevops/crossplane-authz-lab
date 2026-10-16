# Cross-Plane Authorization Lab

**Experimental enforcement research for operations spanning AWS and Kubernetes. Not production-ready.**

An operation can be permitted by each individual control plane yet violate a safety constraint when those permissions are composed. This repository tests whether a verifier can detect that condition using bounded, fresh evidence without trusting an agent's claims.

## Architecture

```text
Collector Job (Kubernetes)                Verifier Deployment (Kubernetes)
  scoped Pod GET ── Kubernetes API           TokenReview ── Kubernetes API
  projected API token                         expected SA name + UID + audience
  projected verifier-audience token
          │                                        │
          ├──── HTTPS POST /challenge ────────────►│
          │◄── verifier-issued nonce + execution ──┤
          ├──── HTTPS POST /reports ──────────────►│
          │     observation + SHA-256 + binding     ├─ validate identity and digest
          │                                         ├─ atomically consume nonce
          │◄──────── accept/reject ─────────────────┤
          │                                         │
          └──── NO PRODUCTION AUTHORIZATION ◄───────┘
```

The collector reads only the named fixture Pod through scoped RBAC. The verifier owns the challenge database and TokenReview credentials. TLS trust is configured explicitly; collector and verifier run as separate workloads in disposable kind CI. An accepted report **does not** authorize an AWS or Kubernetes mutation.

## Verified

- Disposable-kind RBAC, separate collector and verifier workloads, CA-validated HTTPS and live TokenReview.
- Audience-scoped collector credentials, verifier-issued challenge, report digest binding and single-use replay protection.
- Negative tests for invalid credentials and malformed observations.
- Scoped AWS S3 positive/negative probes in earlier CI; these do **not** establish the full cross-plane invariant.

See [Kubernetes integration workflow](.github/workflows/kubernetes-integration.yml), [collector](src/cpal/collector_submit.py), [verifier](src/cpal/report_http.py), and [evidence gate](src/cpal/evidence_gate.py).

## Security boundary

**Production authorization is disabled.** A valid ServiceAccount bearer token proves token possession, not that a collector's reported bytes faithfully represent cluster state. The evidence gate deliberately returns `INDEPENDENT_COLLECTOR_ATTESTATION_REQUIRED` even for otherwise valid evidence.

Current limitations include pod-local SQLite challenge state, verifier token read at startup, test-only TLS provisioning, and incomplete cross-system failure testing. Do not expose this prototype as a production authorization endpoint.

## Run tests

```bash
python -m pip install -e .
python -m unittest discover -s tests
```

The [Kubernetes integration workflow](.github/workflows/kubernetes-integration.yml) creates and removes disposable kind fixtures. It is the reference for the live multi-workload test; the deployment YAML requires CI-provisioned certificates and ConfigMaps.

## Release gates

[Production admission checklist](scenarios/cross-system-invariant/production-readiness-gates.md): independent observation provenance, complete AWS–Kubernetes invariant tests, token rotation, durable state, adversarial review, runtime hardening, operational runbooks and staging soak. **Release decision: NO-GO.**

## Research criterion

Compare against existing IAM, Kubernetes RBAC/admission, policy-as-code and workflow controls. Reject the thesis if existing mechanisms preserve the same invariant with equivalent correctness and lower operational cost. Unknown state must never be treated as permission.
