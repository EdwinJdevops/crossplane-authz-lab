# Live AWS S3 effective-access experiment — 2026-10-10

## Scope

Disposable AWS account `814787354733`, region `us-east-1`, bucket `cpal-probe-814787354733-20261010`, role `arn:aws:iam::814787354733:role/cpal-disposable-s3-probe`. The GitHub Actions workflow authenticated to AWS using OIDC and called STS AssumeRole; the resulting temporary role session executed S3 GetObject against two existing harmless objects.

## Observations

| Control | GitHub Actions run | Key | Observed outcome | Error code |
|---|---|---|---|---|
| Positive | [38055369164](https://github.com/EdwinJdevops/crossplane-authz-lab/actions/runs/38055369164) | `allowed.txt` | `GET_OBJECT_SUCCEEDED` | `null` |
| Negative | [38055552402](https://github.com/EdwinJdevops/crossplane-authz-lab/actions/runs/38055552402) | `denied.txt` | `GET_OBJECT_ACCESS_DENIED` | `AccessDenied` |

Both job logs reported `arn:aws:sts::814787354733:assumed-role/cpal-disposable-s3-probe/cpal-effective-access-probe`. The outcomes were inspected directly from the GitHub Actions job logs. Green workflow status alone is **not** the negative-control verdict: the script treats an expected AccessDenied as an observed outcome, not a process failure.

## Limits of evidence

These observations support object-specific effective access for the observed temporary role sessions and times. They do **not** establish Kubernetes pod identity, IRSA assumption from a pod, complete network paths, IAM policy completeness under subsequent state changes, or compositional cross-control-plane safety. The report is a human-readable record linking to hosted job logs, **not** a signed attestation or authenticated ingestion into the authorization engine. The existing `trusted_probe` and `collector_contract` entry points deliberately return `INSUFFICIENT_EVIDENCE` without authenticated collector evidence.

## Cleanup

After the controls, the two objects, S3 bucket, probe role, and both temporary inline policies were deleted. Independent AWS read-back returned no matching test bucket or probe role and no inline policies on the retained GitHub OIDC bootstrap role. The OIDC provider and permissionless bootstrap role remain for future controlled experiments. The temporary OIDC-claims diagnostic was removed from `main`.

## Next falsification gate

Build a collector with independently authenticated execution provenance and state-bound evidence, then test stale policy, object replacement, mismatched execution ID, and replay. Do not convert these historical logs into an authorization `ALLOW` decision.
