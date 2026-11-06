import base64
import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from cpal.challenge_store import ChallengeStore
from cpal.report_handler import handle_submission
from cpal.tokenreview_result import TokenReviewResult
from scripts.run_verifier import main, make_aws_config


class CrossplaneSubmissionTests(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.store = ChallengeStore(os.path.join(temp, 'challenge.db'))
        self.challenge = self.store.issue(principal='collector', execution_id='execution', now=100)
        self.account = '123456789012'
        self.arn = f'arn:aws:sts::{self.account}:assumed-role/cpal-verifier/staging'
        self.sts = Mock()
        self.sts.get_caller_identity.return_value = {'Account': self.account, 'Arn': self.arn, 'UserId': 'role-id:staging'}
        self.auth = self.enterContext(patch('cpal.challenge_verified_report.authenticate_collector',
            return_value=TokenReviewResult(True, 'collector', 'MATCH')))
        self.enterContext(patch('cpal.independent_pod_observation.ssl.create_default_context'))
        opener = self.enterContext(patch('cpal.independent_pod_observation.urllib.request.build_opener'))
        self.open = opener.return_value.open
        self.live = {'namespace': 'lab', 'name': 'target', 'uid': 'pod-uid', 'resourceVersion': '7'}
        response = self.open.return_value.__enter__.return_value
        response.status = 200
        response.read.side_effect = lambda *_: json.dumps({'kind': 'Pod', 'metadata': self.live}).encode()
        self.kwargs = dict(
            bearer_token='candidate', api_url='https://cluster', cluster_ca='ca',
            verifier_token='verifier', expected_username='collector', expected_uid='uid',
            audience='aud', challenge_store=self.store, now=101,
            observation_namespace='lab', observation_pod='target', sts=self.sts,
            expected_aws_account=self.account, expected_aws_arn=self.arn,
        )

    def submit(self, *, execution='execution', observation=None, **options):
        report = json.dumps({
            'apiVersion': 'cpal.dev/v1alpha1',
            'observation': {'kind': 'Pod', **self.live} if observation is None else observation,
            'execution_id': execution,
        }).encode()
        body = json.dumps({
            'report_b64': base64.b64encode(report).decode(),
            'envelope': {'principal': 'collector', 'nonce': self.challenge.nonce,
                         'execution_id': 'execution', 'report_sha256': hashlib.sha256(report).hexdigest()},
        }).encode()
        return handle_submission(body=body, **{**self.kwargs, **options})

    def test_live_source_calls_and_single_use(self):
        self.assertTrue(self.submit().accepted)
        self.sts.get_caller_identity.assert_called_once_with()
        request = self.open.call_args.args[0]
        self.assertEqual(request.full_url, 'https://cluster/api/v1/namespaces/lab/pods/target')
        self.assertEqual(request.get_header('Authorization'), 'Bearer verifier')
        self.assertEqual(self.submit().reason, 'CHALLENGE_NOT_VALID_OR_ALREADY_USED')

    def test_authentication_precedes_dependency_checks(self):
        self.auth.return_value = TokenReviewResult(False, None, 'DENIED')
        self.assertEqual(self.submit().reason, 'IDENTITY_NOT_VERIFIED')
        self.sts.get_caller_identity.assert_not_called()
        self.open.assert_not_called()

    def test_mismatches_and_forged_flags_do_not_consume(self):
        for observation, execution in (
            ({'kind': 'Pod', **self.live, 'uid': 'recreated'}, 'execution'),
            ({'kind': 'Pod', **self.live, 'resourceVersion': '6'}, 'execution'),
            ({'kind': 'Pod', **self.live, 'verified_by_api': True}, 'execution'),
            (None, 'different-execution'),
        ):
            with self.subTest(observation=observation, execution=execution):
                self.assertEqual(self.submit(observation=observation, execution=execution).reason,
                                 'INDEPENDENT_OBSERVATION_MISMATCH')
        self.assertTrue(self.submit().accepted)

    def test_wrong_sts_identity_and_both_outages_fail_closed(self):
        operation = self.sts.get_caller_identity
        correct = operation.return_value
        operation.return_value = {**correct, 'Arn': self.arn + '-wrong'}
        self.assertEqual(self.submit().reason, 'STS_IDENTITY_MISMATCH')
        operation.return_value = correct
        operation.side_effect = TimeoutError()
        self.assertEqual(self.submit().reason, 'STS_IDENTITY_UNAVAILABLE')
        operation.side_effect = None
        self.open.side_effect = OSError()
        self.assertEqual(self.submit().reason, 'INDEPENDENT_OBSERVATION_MISMATCH')
        self.open.side_effect = None
        self.assertTrue(self.submit().accepted)

    def test_missing_sts_denies_partial_configuration(self):
        self.assertEqual(self.submit(sts=None).reason, 'MISSING_CROSSPLANE_CONFIGURATION')

    def test_challenge_expiring_during_dependency_checks_is_denied(self):
        with patch('cpal.challenge_verified_report.time.monotonic', side_effect=(5, 125)):
            self.assertEqual(self.submit().reason, 'CHALLENGE_NOT_VALID_OR_ALREADY_USED')


class VerifierModeTests(unittest.TestCase):
    def test_production_exits_before_starting_transport(self):
        with patch.dict(os.environ, {'CPAL_PRODUCTION_MODE': '1', 'CPAL_KIND_FIXTURE': '1'}, clear=True):
            with self.assertRaisesRegex(SystemExit, 'INDEPENDENT_COLLECTOR_ATTESTATION_REQUIRED'):
                main()

    def test_missing_staging_identity_fails_startup(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'CPAL_AWS_ACCOUNT'):
                make_aws_config()
