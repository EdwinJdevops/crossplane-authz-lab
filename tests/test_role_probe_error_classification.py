import importlib.util
import unittest
from pathlib import Path


class RoleProbeErrorClassificationTests(unittest.TestCase):
    def test_access_denied_is_not_success(self):
        source = (Path(__file__).resolve().parents[1] / 'scripts/verify_effective_s3_role.py').read_text()
        self.assertIn("'GET_OBJECT_ACCESS_DENIED' if code in {'AccessDenied', '403'}", source)

    def test_missing_key_is_not_classified_as_denied(self):
        source = (Path(__file__).resolve().parents[1] / 'scripts/verify_effective_s3_role.py').read_text()
        self.assertIn("else 'GET_OBJECT_INCONCLUSIVE'", source)
        self.assertIn("'aws_error_code': error_code", source)

if __name__ == '__main__':
    unittest.main()
