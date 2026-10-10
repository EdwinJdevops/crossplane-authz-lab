import unittest
from cpal.aws_state_collector import collect_scoped_state

class FakeIam:
    def get_role(self, **kwargs):
        return {'Role': {'Arn': 'arn:aws:iam::123456789012:role/example'}}
    def list_role_policies(self, **kwargs):
        return {'PolicyNames': [], 'IsTruncated': False}

class FakeS3:
    def head_object(self, **kwargs):
        return {'ETag': 'example', 'ContentLength': 3}

class SnapshotTests(unittest.TestCase):
    def test_snapshot_is_stable_and_incomplete(self):
        args = dict(role_name='example', bucket='fixture', key='sample')
        first = collect_scoped_state(FakeIam(), FakeS3(), **args)
        second = collect_scoped_state(FakeIam(), FakeS3(), **args)
        self.assertEqual(first, second)
        self.assertFalse(first.complete)
        self.assertEqual(first.object_observation, 'HEAD_SUCCEEDED')

if __name__ == '__main__':
    unittest.main()
