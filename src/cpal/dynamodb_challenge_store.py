"""DynamoDB-backed challenge store for multi-replica verifiers.

Requires a dedicated table with partition key `nonce` (String), IAM restricted
to PutItem and UpdateItem on that table, and a TTL attribute `expires_at`.
DynamoDB TTL deletion is asynchronous; conditional updates enforce expiry.
"""
import secrets
import time

from cpal.challenge_store import Challenge


class DynamoDBChallengeStore:
    def __init__(self, table):
        self.table = table

    def issue(self, *, principal: str, execution_id: str, now: int | None = None, ttl: int = 120) -> Challenge:
        if not isinstance(principal, str) or not principal or not isinstance(execution_id, str) or not execution_id or not 1 <= ttl <= 300:
            raise ValueError('invalid challenge parameters')
        issued = int(time.time()) if now is None else now
        challenge = Challenge(secrets.token_urlsafe(32), principal, execution_id, issued + ttl)
        self.table.put_item(Item={'nonce': challenge.nonce, 'principal': principal, 'execution_id': execution_id, 'expires_at': challenge.expires_at, 'consumed': False}, ConditionExpression='attribute_not_exists(nonce)')
        return challenge

    def consume(self, *, nonce: str, principal: str, execution_id: str, now: int | None = None) -> bool:
        if not all(isinstance(x, str) and x for x in (nonce, principal, execution_id)):
            return False
        instant = int(time.time()) if now is None else now
        try:
            self.table.update_item(Key={'nonce': nonce}, UpdateExpression='SET #consumed = :true', ConditionExpression='principal = :principal AND execution_id = :execution AND expires_at > :now AND #consumed = :false', ExpressionAttributeNames={'#consumed': 'consumed'}, ExpressionAttributeValues={':principal': principal, ':execution': execution_id, ':now': instant, ':false': False, ':true': True})
            return True
        except Exception as exc:
            # Only a conditional mismatch is a normal replay/expiry rejection.
            # Network, throttling and permissions failures must propagate to
            # the caller, which rejects with CHALLENGE_STORE_UNAVAILABLE.
            code = getattr(exc, 'response', {}).get('Error', {}).get('Code') if isinstance(getattr(exc, 'response', None), dict) else None
            if code == 'ConditionalCheckFailedException':
                return False
            raise
