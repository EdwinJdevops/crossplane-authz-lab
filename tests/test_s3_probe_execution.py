import ast
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/verify_effective_s3_role.py'
TREE = ast.parse(SOURCE.read_text())
FUNCTIONS = [n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name in {'probe', 'classify_get_error'}]
NAMESPACE = {'boto3': None, 'ClientError': Exception}
exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), str(SOURCE), 'exec'), NAMESPACE)

class FakeBody:
    def __init__(self): self.closed = False
    def close(self): self.closed = True

class FakeSTS:
    def assume_role(self, **kwargs):
        assert kwargs['DurationSeconds'] == 900
        return {'Credentials': {'AccessKeyId':'TEST', 'SecretAccessKey':'TEST', 'SessionToken':'TEST'}}
    def get_caller_identity(self):
        return {'Arn':'arn:aws:sts::111122223333:assumed-role/probe/session'}

class FakeS3:
    def __init__(self): self.body = FakeBody(); self.requests = []
    def get_object(self, **kwargs):
        self.requests.append(kwargs)
        return {'Body':self.body}

class FakeSession:
    def __init__(self, s3): self.s3 = s3
    def client(self, service): return FakeSTS() if service == 'sts' else self.s3

class FakeBoto3:
    def __init__(self, s3): self.s3 = s3
    def client(self, service, **kwargs): return FakeSTS()
    def Session(self, **kwargs):
        assert kwargs['aws_session_token'] == 'TEST'
        return FakeSession(self.s3)

class ProbeExecutionTests(unittest.TestCase):
    def test_get_object_uses_assumed_session_and_closes_body(self):
        s3 = FakeS3()
        NAMESPACE['boto3'] = FakeBoto3(s3)
        result = NAMESPACE['probe']('arn:aws:iam::111122223333:role/probe', 'bucket', 'fixture/ok', 'us-east-1')
        self.assertEqual(s3.requests, [{'Bucket':'bucket', 'Key':'fixture/ok'}])
        self.assertTrue(s3.body.closed)
        self.assertEqual(result['get_object_outcome'], 'GET_OBJECT_SUCCEEDED')
        self.assertIsNone(result['aws_error_code'])

if __name__ == '__main__': unittest.main()
