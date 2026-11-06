"""Bounded staging HTTP load probe. Does not grant production authorization.

Uses standard library only. Requires explicitly configured HTTPS staging URL.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import json
from pathlib import Path
import ssl
import statistics
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def authenticated_probe(args):
    token = Path(args.token_file).read_text(encoding='utf-8').strip()
    observation = json.loads(Path(args.observation_file).read_text(encoding='utf-8'))
    context = ssl.create_default_context(cafile=args.ca)
    origin = args.url.rstrip('/')

    def send(path, body=b''):
        request = urllib.request.Request(
            origin + path, data=body, method='POST',
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
        )
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
        try:
            response = opener.open(request, timeout=args.timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            try:
                result = json.loads(response.read(4096))
            except ValueError:
                result = {}
            return response.code, result

    def build(challenge, *, pod=observation, execution_id=None):
        report = json.dumps({
            'apiVersion': 'cpal.dev/v1alpha1', 'observation': pod,
            'execution_id': execution_id or challenge['execution_id'],
        }).encode()
        return json.dumps({
            'report_b64': base64.b64encode(report).decode(),
            'envelope': {
                'principal': args.principal, 'nonce': challenge['nonce'],
                'execution_id': challenge['execution_id'],
                'report_sha256': hashlib.sha256(report).hexdigest(),
            },
        }).encode()

    def issue():
        status, result = send('/challenge')
        if status != 200 or result.get('accepted') is not True:
            raise SystemExit('FAIL: authenticated challenge issuance failed')
        return result

    def expect(path, body, status, reason):
        if send(path, body) != (status, {'accepted': status == 200, 'reason': reason}):
            raise SystemExit('FAIL: unexpected result for ' + reason)

    if args.expect_denial in ('COLLECTOR_NOT_AUTHENTICATED', 'CHALLENGE_STORE_UNAVAILABLE'):
        expect('/challenge', b'', 403, args.expect_denial)
        print(json.dumps({'challenge_denial': args.expect_denial}))
        return
    challenge = issue()
    body = build(challenge)
    if args.expect_denial:
        expect('/reports', body, 403, args.expect_denial)
        print(json.dumps({'report_denial': args.expect_denial}))
        return
    for forged in (
        build(challenge, pod={**observation, 'uid': 'forged'}),
        build(challenge, execution_id=challenge['execution_id'] + '-stale'),
        build(challenge, pod={**observation, 'verified_by_api': True}),
    ):
        expect('/reports', forged, 403, 'INDEPENDENT_OBSERVATION_MISMATCH')

    def race(_):
        start = time.monotonic()
        status, result = send('/reports', body)
        return status, result, (time.monotonic() - start) * 1000

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        outcomes = list(pool.map(race, range(args.requests)))
    winners = sum((status, result) == (200, {'accepted': True, 'reason': 'VERIFIED_CHALLENGE_REPORT'}) for status, result, _ in outcomes)
    replays = sum((status, result) == (403, {'accepted': False, 'reason': 'CHALLENGE_NOT_VALID_OR_ALREADY_USED'}) for status, result, _ in outcomes)
    if winners != 1 or replays != args.requests - 1:
        raise SystemExit(f'FAIL: authenticated race accepted={winners} replay_denials={replays}')
    expect('/reports', build(issue()), 200, 'VERIFIED_CHALLENGE_REPORT')
    durations = sorted(duration for _, _, duration in outcomes)
    print(json.dumps({
        'requests': args.requests, 'accepted': winners, 'replay_denials': replays,
        'p95_ms': round(durations[min(len(durations) - 1, int(len(durations) * .95))], 2),
        'fresh_challenge_accepted': True,
    }))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--requests', type=int, default=100)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--timeout', type=float, default=5)
    parser.add_argument('--token-file')
    parser.add_argument('--observation-file')
    parser.add_argument('--principal')
    parser.add_argument('--ca')
    parser.add_argument('--expect-denial', choices=(
        'STS_IDENTITY_UNAVAILABLE', 'STS_IDENTITY_MISMATCH',
        'INDEPENDENT_OBSERVATION_MISMATCH', 'COLLECTOR_NOT_AUTHENTICATED',
        'CHALLENGE_STORE_UNAVAILABLE',
    ))
    args = parser.parse_args()
    parsed = urlsplit(args.url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query or parsed.path not in ('', '/'):
        parser.error('URL must be a bare HTTPS staging origin')
    if not 1 <= args.requests <= 1000 or not 1 <= args.workers <= 32 or not 0.1 <= args.timeout <= 30:
        parser.error('bounded load parameters required')
    if any((args.token_file, args.observation_file, args.principal, args.ca, args.expect_denial)):
        if not all((args.token_file, args.observation_file, args.principal, args.ca)):
            parser.error('authenticated probes require token file, observation file, principal and CA')
        if not args.expect_denial and min(args.requests, args.workers) < 2:
            parser.error('authenticated replay race requires at least two requests and two workers')
        authenticated_probe(args)
        return
    target = args.url.rstrip('/') + '/challenge'
    def probe(_):
        start = time.monotonic()
        try:
            # Intentionally unauthenticated: must always deny; never issues ledger entries.
            req = urllib.request.Request(target, data=b'', method='POST')
            with urllib.request.build_opener(urllib.request.HTTPSHandler(), NoRedirect()).open(req, timeout=args.timeout) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        except (OSError, urllib.error.URLError):
            status = 0
        return status, (time.monotonic() - start) * 1000
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        outcomes = list(pool.map(probe, range(args.requests)))
    statuses = [status for status, _ in outcomes]
    durations = sorted(duration for _, duration in outcomes)
    p95 = durations[min(len(durations)-1, int(len(durations)*0.95))]
    print(json.dumps({'requests':len(statuses),'statuses':{str(s):statuses.count(s) for s in sorted(set(statuses))},'p95_ms':round(p95,2),'mean_ms':round(statistics.mean(durations),2)}))
    if any(status not in (401,403) for status in statuses):
        raise SystemExit('FAIL: unauthorized probe did not consistently fail closed')


if __name__ == '__main__':
    main()
