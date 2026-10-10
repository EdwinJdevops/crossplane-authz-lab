import unittest
from pathlib import Path

WORKFLOW = (Path(__file__).resolve().parents[1] / '.github/workflows/manual-s3-probe.yml').read_text()

class ManualProbeWorkflowTests(unittest.TestCase):
    def test_manual_only_and_oidc(self):
        self.assertIn('workflow_dispatch:', WORKFLOW)
        self.assertNotIn('\n  push:', WORKFLOW)
        self.assertNotIn('\n  schedule:', WORKFLOW)
        self.assertIn('id-token: write', WORKFLOW)
        self.assertIn('environment: aws-experiment', WORKFLOW)
        self.assertIn('aws-actions/configure-aws-credentials@v4', WORKFLOW)

    def test_no_static_credentials_or_administrator_policy(self):
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', WORKFLOW)
        self.assertNotIn('AdministratorAccess', WORKFLOW)
        self.assertIn('CPAL_GITHUB_OIDC_ROLE_ARN', WORKFLOW)

if __name__ == '__main__': unittest.main()
