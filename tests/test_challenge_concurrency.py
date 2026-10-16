import concurrent.futures
import os
import tempfile
import unittest

from cpal.challenge_store import ChallengeStore


class ChallengeConcurrencyTests(unittest.TestCase):
    def test_only_one_concurrent_consumer_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'challenges.sqlite3')
            challenge = ChallengeStore(path).issue(principal='collector', execution_id='execution', now=100, ttl=60)
            def attempt(_):
                return ChallengeStore(path).consume(nonce=challenge.nonce, principal='collector', execution_id='execution', now=110)
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                results = list(pool.map(attempt, range(48)))
            self.assertEqual(sum(results), 1)
            self.assertFalse(ChallengeStore(path).consume(nonce=challenge.nonce, principal='collector', execution_id='execution', now=110))

    def test_reopened_store_preserves_unconsumed_challenge(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'challenges.sqlite3')
            challenge = ChallengeStore(path).issue(principal='collector', execution_id='execution', now=100, ttl=60)
            self.assertFalse(ChallengeStore(path).consume(nonce=challenge.nonce, principal='wrong', execution_id='execution', now=110))
            self.assertFalse(ChallengeStore(path).consume(nonce=challenge.nonce, principal='collector', execution_id='execution', now=161))
            self.assertTrue(ChallengeStore(path).consume(nonce=challenge.nonce, principal='collector', execution_id='execution', now=110))


if __name__ == '__main__':
    unittest.main()
