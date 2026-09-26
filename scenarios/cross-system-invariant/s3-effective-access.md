# Effective S3 access: evidence requirements

The lab does not implement an IAM policy evaluator.

AWS IAM already defines policy evaluation. The problem here is determining whether the evidence available to the cross-plane authorization decision is sufficient to make the stronger live-system claim.

For the narrow E1 GetObject case, the evidence contract tracks identity policy, permissions boundary, SCP, bucket/resource policy, RCP, and VPC endpoint policy where the request path uses one. If the protected object is SSE-KMS encrypted, KMS decrypt authorization is an additional requirement.

The IAM policy simulator is useful evidence but is not treated as complete live proof. AWS documents differences from the live environment and limitations including RCPs, VPC endpoint policies, role chaining and resource-based policy simulation for IAM roles.

The composition rule is deliberately small:

- any authoritative required DENY => DENIED;
- any unresolved required component => UNKNOWN;
- SATISFIED only when every declared required component has authoritative satisfied evidence.

This is evidence composition, not AWS authorization reimplementation.

## Falsification consequence

If AWS exposes a production API that already returns the complete effective live authorization result for the exact role/session, S3 object, request context, organization controls, endpoint path and KMS dependency without executing the protected read, this layer should be deleted and that API used directly.

Until such a primitive is established, the lab must retain UNKNOWN rather than infer access from an incomplete simulator result.
