# Live assumed-role S3 authorization probe

Status: **NOT EXECUTED**. GitHub CI validates repository tests; it does not prove live AWS role access.

## Preconditions

Use a disposable private bucket and harmless test object in the same account. Create a dedicated role with a trust policy allowing **only the designated test principal** to call `sts:AssumeRole`. Do not trust the whole account root or allow wildcard principals. Give that role only `s3:GetObject` on the exact test object ARN. Use a caller profile with permission to assume the role. Record the bucket region and account, and keep public access blocked. Avoid production data.

## Positive control

Run from an authorized AWS environment with `boto3` and `botocore` installed:

```sh
python scripts/verify_effective_s3_role.py --role-arn "$ROLE_ARN" --bucket "$BUCKET" --key fixture/probe.txt --region us-east-1
```

Require `GET_OBJECT_SUCCEEDED`, an STS assumed-role ARN, and the exact requested bucket/key. This proves a read succeeded *for that session, object, and time*. It does not prove every principal or workload can read it.

## Negative control

Run the same script using a different existing object key that the role does **not** have permission to read. Ensure the object actually exists; otherwise `NoSuchKey` or a 404 response is inconclusive. Require `GET_OBJECT_ACCESS_DENIED`. The probe deliberately does not attempt `DeleteObject`.

## Evidence integrity

Store UTC time, AWS account, assumed-role session ARN, role ARN, bucket, object key, region, outcome, and policy/trust-policy digests. Never store credentials, session tokens, or object contents. Re-read relevant policies and object identity before interpreting results. An actual read and denied control demonstrate effective authorization for the tested session, but do **not** prove Kubernetes IRSA, EKS network reachability, or complete dependency closure.

## Cleanup and verification

Remove only the disposable test object, bucket, role policies, and role created for this experiment. Independently verify the role no longer exists and the bucket is absent. Record any failure rather than claiming full cleanup. Do not assume zero AWS cost.

## Next gate

Bind verified AWS evidence to the precise Kubernetes Service → workload → ServiceAccount → role path, with current state digests. Missing or unsupported identity/network/policy edges must yield `INSUFFICIENT_EVIDENCE`. Compare outcomes against a complete-evidence OPA baseline.
