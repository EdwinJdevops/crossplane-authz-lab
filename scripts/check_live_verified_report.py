"""Disposable kind integration: real TokenReview plus report digest and replay."""
import hashlib
import os
import subprocess
import tempfile
import time

from cpal.sqlite_replay import SQLiteReplayLedger
from cpal.verified_report import verify_report


def kubectl(*args):
    return subprocess.check_output(['kubectl', *args], text=True).strip()


def main():
    ns = 'cpal-experiment'
    audience = 'cpal-collector-verification'
    candidate = kubectl('-n', ns, 'create', 'token', 'cpal-collector', '--audience=' + audience, '--duration=10m')
    verifier = kubectl('-n', ns, 'create', 'token', 'cpal-token-verifier', '--duration=10m')
    uid = kubectl('-n', ns, 'get', 'serviceaccount', 'cpal-collector', '-o', 'jsonpath={.metadata.uid}')
    ca = kubectl('-n', ns, 'get', 'configmap', 'kube-root-ca.crt', '-o', 'jsonpath={.data.ca\\.crt}')
    endpoint = kubectl('config', 'view', '--minify', '-o', 'jsonpath={.clusters[0].cluster.server}')
    report = b'{"resource":"cpal-target","status":"observed"}'
    now = int(time.time())
    principal = 'system:serviceaccount:cpal-experiment:cpal-collector'
    envelope = dict(principal=principal, nonce='live-nonce-1', execution_id='live-execution-1', report_sha256=hashlib.sha256(report).hexdigest(), expires_at=now + 120)
    with tempfile.TemporaryDirectory() as directory:
        ca_path = os.path.join(directory, 'ca.crt')
        with open(ca_path, 'w', encoding='utf-8') as f:
            f.write(ca)
        ledger = SQLiteReplayLedger(os.path.join(directory, 'replay.sqlite'))
        args = dict(report=report, envelope=envelope, candidate_token=candidate, api_url=endpoint, cluster_ca=ca_path, verifier_token=verifier, expected_username=principal, expected_uid=uid, audience=audience, expected_nonce='live-nonce-1', expected_execution='live-execution-1', ledger=ledger, now=now)
        altered = verify_report(**{**args, 'report':b'altered'})
        if altered.reason != 'REPORT_DIGEST_MISMATCH':
            raise RuntimeError('Tampered report not rejected: ' + altered.reason)
        print('Live composed verifier: tampered report rejected', flush=True)
        valid = verify_report(**args)
        if not valid.accepted:
            raise RuntimeError('Valid report rejected: ' + valid.reason)
        print('Live composed verifier: authenticated report accepted', flush=True)
        replay = verify_report(**args)
        if replay.reason != 'REPLAY_DETECTED':
            raise RuntimeError('Replay not rejected: ' + replay.reason)
        print('Live composed verifier: replay rejected', flush=True)
        wrong_uid = verify_report(**{**args, 'expected_uid':'wrong-uid', 'envelope':{**envelope, 'nonce':'new-nonce'}, 'expected_nonce':'new-nonce'})
        if wrong_uid.accepted or wrong_uid.reason != 'IDENTITY_IDENTITY_MISMATCH':
            raise RuntimeError('Wrong identity not rejected: ' + wrong_uid.reason)
        print('Live composed verifier: wrong UID rejected', flush=True)


if __name__ == '__main__':
    main()
