"""Opt-in live DynamoDB probe against an explicitly supplied disposable table.

Never provisions or deletes infrastructure. Run with CPAL_DYNAMODB_CHALLENGE_TABLE
and AWS credentials scoped to that table. Exit nonzero on any failed invariant.
"""
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from cpal.dynamodb_challenge_store import DynamoDBChallengeStore


def run(table):
    first = DynamoDBChallengeStore(table)
    second = DynamoDBChallengeStore(table)
    now = int(time.time())
    challenge = first.issue(principal='cpal-probe', execution_id='probe-' + str(now), now=now, ttl=60)
    args = dict(nonce=challenge.nonce, principal=challenge.principal, execution_id=challenge.execution_id, now=now + 1)
    with ThreadPoolExecutor(max_workers=12) as pool:
        outcomes = list(pool.map(lambda i: (first if i % 2 else second).consume(**args), range(48)))
    assert outcomes.count(True) == 1, 'conditional claim not atomic'
    assert first.consume(**args) is False, 'replay accepted'
    # Reconstruct the store to simulate process restart; state must survive.
    restarted = DynamoDBChallengeStore(table)
    assert restarted.consume(**args) is False, 'restart resurrected consumed challenge'
    expired = first.issue(principal='cpal-probe', execution_id='expiry', now=now - 120, ttl=60)
    assert not second.consume(nonce=expired.nonce, principal=expired.principal, execution_id=expired.execution_id, now=now), 'expired challenge accepted'
    wrong = first.issue(principal='cpal-probe', execution_id='identity', now=now, ttl=60)
    assert not second.consume(nonce=wrong.nonce, principal='forged', execution_id=wrong.execution_id, now=now), 'wrong principal accepted'
    assert first.consume(nonce=wrong.nonce, principal=wrong.principal, execution_id=wrong.execution_id, now=now), 'wrong principal consumed valid challenge'
    print('PASS live DynamoDB: atomic 48-way claim, replay, restart, expiry, principal binding')


def main():
    name = os.environ.get('CPAL_DYNAMODB_CHALLENGE_TABLE')
    if not name:
        raise SystemExit('CPAL_DYNAMODB_CHALLENGE_TABLE is required')
    import boto3
    run(boto3.resource('dynamodb').Table(name))


if __name__ == '__main__':
    main()
