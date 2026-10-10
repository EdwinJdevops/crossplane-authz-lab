# Manual GitHub Actions AWS probe setup

This workflow is **not configured for live execution** by merely committing it. It requires an AWS OIDC provider, an explicitly scoped GitHub Actions bootstrap role, a disposable S3 fixture, a restricted probe role, and a GitHub environment named `aws-experiment` with appropriate approval rules.

Set environment variable `CPAL_GITHUB_OIDC_ROLE_ARN` to the bootstrap role ARN. The bootstrap role must trust `token.actions.githubusercontent.com` with `aud=sts.amazonaws.com` and `sub` constrained to `repo:EdwinJdevops/crossplane-authz-lab:environment:aws-experiment`. Grant only `sts:AssumeRole` on the specific disposable probe role. Do not attach AdministratorAccess or broad S3 access to this bootstrap role.

The disposable probe role must trust the bootstrap role (not arbitrary principals), and have only `s3:GetObject` on the intended harmless object. Create a second existing harmless object outside that policy's resource ARN for a negative control. Run the manual workflow separately for each object, and preserve run IDs, timestamps, and outcomes. The script does not delete any resources.

**Security boundaries:** GitHub OIDC proves the calling workflow identity to AWS STS; it does not by itself authenticate a report later copied into another system. Workflow logs are not signed attestations. Require a separate trusted evidence ingestion design before using these results for production authorization.

**Operational caution:** This workflow is manual and has no schedule or push trigger. Do not run against production buckets, objects, or roles. Inspect the workflow and IAM trust policies before enabling the GitHub environment. The workflow may fail until the OIDC provider and environment are configured. A successful CI unit test is not a successful live probe.
