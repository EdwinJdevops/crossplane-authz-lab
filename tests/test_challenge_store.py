import concurrent.futures
import os
import tempfile
import unittest
from cpal.challenge_store import ChallengeStore


class ChallengeStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ChallengeStore(os.path.join(self.temp.name, 'challenges.sqlite'))

    def test_issue_and_single_use(self):
        challenge = self.store.issue(principal='collector', execution_id='e1', now=1000)
        self.assertTrue(self.store.consume(nonce=challenge.nonce, principal='collector', execution_id='e1', now=1001))
        self.assertFalse(self.store.consume(nonce=challenge.nonce, principal='collector', execution_id='e1', now=1002))

    def test_mismatch_does_not_burn_challenge(self):
        c = self.store.issue(principal='collector', execution_id='e1', now=1000)
        self.assertFalse(self.store.consume(nonce=c.nonce, principal='attacker', execution_id='e1', now=1001))
        self.assertFalse(self.store.consume(nonce=c.nonce, principal='collector', execution_id='other', now=1001))
        self.assertTrue(self.store.consume(nonce=c.nonce, principal='collector', execution_id='e1', now=1001))

    def test_expired(self):
        c = self.store.issue(principal='collector', execution_id='e1', now=1000, ttl=1)
        self.assertFalse(self.store.consume(nonce=c.nonce, principal='collector', execution_id='e1', now=1001))

    def test_concurrent_claim_only_one_wins(self):
        c = self.store.issue(principal='collector', execution_id='e1', now=1000)
        def claim(_):
            return self.store.consume(nonce=c.nonce, principal='collector', execution_id='e1', now=1001)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(claim, range(16))), 1)

    def test_nonce_is_random(self):
        a = self.store.issue(principal='collector', execution_id='e1', now=1000)
        b = self.store.issue(principal='collector', execution_id='e1', now=1000)
        self.assertNotEqual(a.nonce, b.nonce)


if __name__ == '__main__':
    unittest.main()
