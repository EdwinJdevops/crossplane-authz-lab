import ast
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/verify_effective_s3_role.py'
TREE = ast.parse(SOURCE.read_text())
CLASSIFIER = next(node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name == 'classify_get_error')
NAMESPACE = {}
exec(compile(ast.Module(body=[CLASSIFIER], type_ignores=[]), str(SOURCE), 'exec'), NAMESPACE)


class RoleProbeErrorClassificationTests(unittest.TestCase):
    def test_access_denied(self):
        self.assertEqual(NAMESPACE['classify_get_error']('AccessDenied'), 'GET_OBJECT_ACCESS_DENIED')
        self.assertEqual(NAMESPACE['classify_get_error']('403'), 'GET_OBJECT_ACCESS_DENIED')

    def test_missing_key_and_other_errors_are_inconclusive(self):
        for code in ('NoSuchKey', '404', 'InternalError', 'UNKNOWN'):
            with self.subTest(code=code):
                self.assertEqual(NAMESPACE['classify_get_error'](code), 'GET_OBJECT_INCONCLUSIVE')

if __name__ == '__main__':
    unittest.main()
