import unittest
from cpal.aws_state_collector import collect_scoped_state

class FakeIam:
    def get_role(self, **kwargs):
        return {'Role': {'Arn': 'arn:aws:iam::123456789012:role/example'}}
    def list_role_policies(self, **kwargs):
        return {'PolicyNames': [], 'IsTruncated': False}

class FakeS3:
    def __init__(self, etag, broken=False):
        self.etag = etag
        self.broken = broken
    def head_object(self, **kwargs):
        if self.broken:
            raise RuntimeError('metadata unavailable')
        return {'ETag': self.etag, 'ContentLength': 3}

class SnapshotChangeTests(unittest.TestCase):
    def test_metadata_change_changes_digest(self):
        args = dict(role_name='example', bucket='fixture', key='sample')
        before = collect_scoped_state(FakeIam(), FakeS3('one'), **args)
        after = collect_scoped_state(FakeIam(), FakeS3('two'), **args)
        self.assertNotEqual(before.object_metadata_digest, after.object_metadata_digest)
    def test_errors_propagate(self):
        with self.assertRaises(RuntimeError):
            collect_scoped_state(FakeIam(), FakeS3('one', broken=True), role_name='example', bucket='fixture', key='sample')

if __name__ == '__main__':
    unittest.main()
