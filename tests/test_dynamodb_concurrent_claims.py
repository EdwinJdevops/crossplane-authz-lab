import concurrent.futures
import threading
import unittest

from cpal.dynamodb_challenge_store import DynamoDBChallengeStore


class ConditionalFailure(Exception):
    response = {'Error': {'Code': 'ConditionalCheckFailedException'}}


class AtomicTable:
    def __init__(self):
        self.items = {}
        self.lock = threading.Lock()
    def put_item(self, *, Item, ConditionExpression):
        with self.lock:
            if Item['nonce'] in self.items:
                raise ConditionalFailure()
            self.items[Item['nonce']] = dict(Item)
    def update_item(self, *, Key, UpdateExpression, ConditionExpression, ExpressionAttributeValues, ExpressionAttributeNames):
        with self.lock:
            item = self.items.get(Key['nonce'])
            values = ExpressionAttributeValues
            if not item or item['consumed'] or item['principal'] != values[':principal'] or item['execution_id'] != values[':execution'] or item['expires_at'] <= values[':now']:
                raise ConditionalFailure()
            item['consumed'] = True


class ConcurrentClaimTests(unittest.TestCase):
    def test_only_one_replica_wins(self):
        table = AtomicTable()
        challenge = DynamoDBChallengeStore(table).issue(principal='p', execution_id='e', now=100)
        def claim(_):
            return DynamoDBChallengeStore(table).consume(nonce=challenge.nonce, principal='p', execution_id='e', now=101)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            self.assertEqual(sum(pool.map(claim, range(128))), 1)


if __name__ == '__main__':
    unittest.main()
