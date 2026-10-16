"""Bounded staging HTTP load probe. Does not grant production authorization.

Uses standard library only. Requires explicitly configured HTTPS staging URL.
"""
import argparse
import concurrent.futures
import json
import statistics
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--requests', type=int, default=100)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--timeout', type=float, default=5)
    args = parser.parse_args()
    parsed = urlsplit(args.url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query or parsed.path not in ('', '/'):
        parser.error('URL must be a bare HTTPS staging origin')
    if not 1 <= args.requests <= 1000 or not 1 <= args.workers <= 32 or not 0.1 <= args.timeout <= 30:
        parser.error('bounded load parameters required')
    target = args.url.rstrip('/') + '/challenge'
    def probe(_):
        start = time.monotonic()
        try:
            # Intentionally unauthenticated: must always deny; never issues ledger entries.
            req = urllib.request.Request(target, data=b'', method='POST')
            with urllib.request.urlopen(req, timeout=args.timeout) as response:
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
