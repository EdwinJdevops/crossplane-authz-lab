"""Live kind: verifier-owned challenge + real Kubernetes TokenReview."""
import hashlib
import os
import subprocess
import tempfile
import time
from cpal.challenge_store import ChallengeStore
from cpal.challenge_verified_report import verify_challenged_report


def k(*args):
    return subprocess.check_output(['kubectl', *args], text=True).strip()


def main():
    ns = 'cpal-experiment'
    principal = f'system:serviceaccount:{ns}:cpal-collector'
    aud = 'cpal-collector-verification'
    token = k('-n', ns, 'create', 'token', 'cpal-collector', '--audience=' + aud, '--duration=10m')
    verifier = k('-n', ns, 'create', 'token', 'cpal-token-verifier', '--duration=10m')
    uid = k('-n', ns, 'get', 'sa', 'cpal-collector', '-o', 'jsonpath={.metadata.uid}')
    ca = k('-n', ns, 'get', 'cm', 'kube-root-ca.crt', '-o', 'jsonpath={.data.ca\\.crt}')
    endpoint = k('config', 'view', '--minify', '-o', 'jsonpath={.clusters[0].cluster.server}')
    now = int(time.time())
    report = b'{"observed":"pod","source":"integration"}'
    with tempfile.TemporaryDirectory() as tmp:
        ca_path = os.path.join(tmp, 'ca.crt')
        with open(ca_path, 'w', encoding='utf-8') as f:
            f.write(ca)
        store = ChallengeStore(os.path.join(tmp, 'challenges.db'))
        challenge = store.issue(principal=principal, execution_id='live-execution', now=now)
        envelope = dict(principal=principal, nonce=challenge.nonce, execution_id=challenge.execution_id, report_sha256=hashlib.sha256(report).hexdigest())
        args = dict(report=report, envelope=envelope, candidate_token=token, api_url=endpoint, cluster_ca=ca_path, verifier_token=verifier, expected_username=principal, expected_uid=uid, audience=aud, challenge_store=store, now=now)
        bad = verify_challenged_report(**{**args, 'report':b'tampered'})
        assert bad.reason == 'REPORT_DIGEST_MISMATCH', bad.reason
        print('Challenge report: tamper rejected', flush=True)
        wrong = verify_challenged_report(**{**args, 'expected_uid':'wrong-uid'})
        assert wrong.reason == 'IDENTITY_NOT_VERIFIED', wrong.reason
        print('Challenge report: identity mismatch rejected', flush=True)
        good = verify_challenged_report(**args)
        assert good.accepted, good.reason
        print('Challenge report: live authenticated verifier-issued nonce accepted', flush=True)
        replay = verify_challenged_report(**args)
        assert replay.reason == 'CHALLENGE_NOT_VALID_OR_ALREADY_USED', replay.reason
        print('Challenge report: replay rejected', flush=True)
        forged = verify_challenged_report(**{**args, 'envelope':{**envelope, 'nonce':'forged'}})
        assert forged.reason == 'CHALLENGE_NOT_VALID_OR_ALREADY_USED', forged.reason
        print('Challenge report: forged challenge rejected', flush=True)


if __name__ == '__main__':
    main()
