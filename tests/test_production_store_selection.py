import os
import unittest
from unittest.mock import patch
from scripts.run_verifier import make_challenge_store


class ProductionStoreSelectionTests(unittest.TestCase):
    def test_production_refuses_sqlite_fallback(self):
        with patch.dict(os.environ, {'CPAL_PRODUCTION_MODE':'1', 'CPAL_CHALLENGE_DB':'/tmp/local.db'}, clear=True):
            with self.assertRaisesRegex(ValueError, 'durable DynamoDB'):
                make_challenge_store()

    def test_disposable_mode_requires_explicit_local_path(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'CPAL_CHALLENGE_DB'):
                make_challenge_store()


if __name__ == '__main__':
    unittest.main()
