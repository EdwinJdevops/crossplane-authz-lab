# Durable challenge state — deployment prerequisites

`dynamodb-challenges.tf` defines an encrypted, on-demand DynamoDB table with TTL and point-in-time recovery. **It has not been applied.** The table is billable, and `prevent_destroy` intentionally requires a reviewed change for teardown. Review AWS region, IAM, backup retention, quotas, budgets and Terraform state before applying.

The verifier needs `dynamodb:PutItem` and `dynamodb:UpdateItem` scoped to the created table ARN. Its Kubernetes identity must be mapped to AWS credentials through a reviewed workload identity mechanism; never mount long-lived AWS access keys in Pods. Set `CPAL_DYNAMODB_CHALLENGE_TABLE` and `CPAL_PRODUCTION_MODE=1` only after the AWS role, network egress, permissions and dependency packaging have been tested.

The current disposable kind deployment uses SQLite and remains nonproduction. DynamoDB TTL is eventual and **not** the security expiry check; the conditional update checks expiry. A conditional update provides a single-winner claim across replicas. Disaster recovery must account for restored challenges and external side effects; do not treat PITR alone as a complete recovery strategy.
