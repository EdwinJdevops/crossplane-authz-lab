import unittest
from cpal.dynamodb_challenge_store import DynamoDBChallengeStore


class AmbiguousWriteTable:
    def __init__(self):
        self.consumed = False
    def put_item(self, *, Item, ConditionExpression):
        self.item = Item
    def update_item(self, *, Key, UpdateExpression, ConditionExpression, ExpressionAttributeValues):
        # Simulate a committed write followed by a lost acknowledgement.
        self.consumed = True
        raise TimeoutError('response lost after commit')


class DynamoDBFailureTests(unittest.TestCase):
    def test_lost_acknowledgement_never_returns_success(self):
        table = AmbiguousWriteTable()
        store = DynamoDBChallengeStore(table)
        challenge = store.issue(principal='p', execution_id='e', now=100)
        with self.assertRaises(TimeoutError):
            store.consume(nonce=challenge.nonce, principal='p', execution_id='e', now=101)
        self.assertTrue(table.consumed)

    def test_invalid_claim_never_calls_storage(self):
        class NeverCalled:
            def update_item(self, **kwargs):
                raise AssertionError('must not call storage')
        self.assertFalse(DynamoDBChallengeStore(NeverCalled()).consume(nonce='', principal='p', execution_id='e'))


if __name__ == '__main__':
    unittest.main()
