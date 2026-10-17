import unittest
from cpal.dynamodb_challenge_store import DynamoDBChallengeStore


class ConditionalFailure(Exception):
    response = {'Error': {'Code': 'ConditionalCheckFailedException'}}


class FakeTable:
    def __init__(self):
        self.items = {}
        self.outage = False

    def put_item(self, *, Item, ConditionExpression):
        assert ConditionExpression == 'attribute_not_exists(nonce)'
        if self.outage:
            raise ConnectionError('unavailable')
        if Item['nonce'] in self.items:
            raise ConditionalFailure()
        self.items[Item['nonce']] = Item.copy()

    def update_item(self, *, Key, UpdateExpression, ConditionExpression, ExpressionAttributeValues, ExpressionAttributeNames):
        if self.outage:
            raise ConnectionError('unavailable')
        item = self.items.get(Key['nonce'])
        values = ExpressionAttributeValues
        if not item or item['consumed'] or item['principal'] != values[':principal'] or item['execution_id'] != values[':execution'] or item['expires_at'] <= values[':now']:
            raise ConditionalFailure()
        item['consumed'] = True


class DynamoChallengeTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        self.first = DynamoDBChallengeStore(self.table)
        self.second = DynamoDBChallengeStore(self.table)
        self.challenge = self.first.issue(principal='collector', execution_id='run', now=100, ttl=60)
        self.claim = dict(nonce=self.challenge.nonce, principal='collector', execution_id='run', now=101)

    def test_shared_replica_single_use(self):
        self.assertTrue(self.second.consume(**self.claim))
        self.assertFalse(self.first.consume(**self.claim))

    def test_wrong_identity_does_not_consume(self):
        self.assertFalse(self.first.consume(**{**self.claim, 'principal':'other'}))
        self.assertTrue(self.second.consume(**self.claim))

    def test_expired_rejected(self):
        self.assertFalse(self.first.consume(**{**self.claim, 'now':160}))

    def test_outage_is_not_replay(self):
        self.table.outage = True
        with self.assertRaises(ConnectionError):
            self.first.consume(**self.claim)
        with self.assertRaises(ConnectionError):
            self.first.issue(principal='collector', execution_id='run', now=100)


if __name__ == '__main__':
    unittest.main()
