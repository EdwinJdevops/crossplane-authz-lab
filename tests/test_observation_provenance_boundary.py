"""Security boundary regression: a collector identity does not prove Pod observations.

These tests demonstrate the unresolved attack; do not interpret acceptance as
production authorization. They guard against misleading release claims.
"""
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch

from cpal.challenge_store import ChallengeStore
from cpal.challenge_verified_report import verify_challenged_report


class ObservationProvenanceBoundaryTests(unittest.TestCase):
    def test_authenticated_collector_can_submit_fabricated_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ChallengeStore(directory + '/challenges.sqlite3')
            challenge = store.issue(principal='collector', execution_id='exec', now=100)
            fabricated = json.dumps({'kind': 'Pod', 'metadata': {'uid': 'invented-uid', 'resourceVersion': '999999'}}).encode()
            envelope = {'nonce': challenge.nonce, 'execution_id': 'exec', 'principal': 'collector', 'report_sha256': hashlib.sha256(fabricated).hexdigest()}
            with patch('cpal.challenge_verified_report.authenticate_collector') as authenticate:
                authenticate.return_value.authenticated = True
                authenticate.return_value.principal = 'collector'
                result = verify_challenged_report(report=fabricated, envelope=envelope, candidate_token='stolen-or-compromised-collector-token', api_url='https://kubernetes', cluster_ca='ca', verifier_token='verifier', expected_username='collector', expected_uid='uid', audience='aud', challenge_store=store, now=101)
            self.assertTrue(result.accepted, 'This is the known provenance gap; the gate MUST stay closed')


if __name__ == '__main__':
    unittest.main()
