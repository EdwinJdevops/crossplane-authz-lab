import json
import tempfile
import unittest
from pathlib import Path
from scripts.check_release_gates import REQUIRED, assess


class ReleaseGateTests(unittest.TestCase):
    def test_missing_evidence_fails_closed(self):
        self.assertFalse(assess('/nonexistent/release-evidence.json')[0])

    def test_partial_evidence_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'release.json'
            path.write_text(json.dumps({REQUIRED[0]: {'approved': True, 'reviewer': 'reviewer', 'evidence_url': 'https://example.com/evidence'}}))
            self.assertFalse(assess(path)[0])

    def test_unapproved_gate_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'release.json'
            record = {name: {'approved': True, 'reviewer': 'reviewer', 'evidence_url': 'https://example.com/evidence'} for name in REQUIRED}
            record['operational_assurance']['approved'] = False
            path.write_text(json.dumps(record))
            self.assertFalse(assess(path)[0])


if __name__ == '__main__':
    unittest.main()
