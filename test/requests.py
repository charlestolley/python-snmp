__all__ = ["RequestIDAuthorityTest", "RequestPollerTest"]

import unittest

from snmp.exception import *
from snmp.numbers import *
from snmp.requests import *
from snmp.scheduler import *

class RequestIDAuthorityTest(unittest.TestCase):
    def setUp(self):
        self.authority = RequestIDAuthority()

    def test_RequestIDAuthority_inherits_from_NumberAuthority(self):
        self.assertIsInstance(self.authority, NumberAuthority)

    def test_reserve_returns_unique_nonzero_32_bit_signed_requestID(self):
        requestIDs = set()

        for _ in range(1000):
            requestID = self.authority.reserve()
            requestIDs.add(requestID)

            self.assertGreaterEqual(requestID, -(1 << 31))
            self.assertLess(requestID, 1 << 31)
            self.assertNotEqual(requestID, 0)

        self.assertEqual(len(requestIDs), 1000)

    def test_AllocationFailure_is_an_SNMPLibraryBug(self):
        exception = self.authority.AllocationFailure(30)
        self.assertIsInstance(exception, SNMPLibraryBug)

    def test_DeallocationFailure_is_an_SNMPLibraryBug(self):
        exception = self.authority.DeallocationFailure(34)
        self.assertIsInstance(exception, SNMPLibraryBug)

class RequestPollerTest(unittest.TestCase):
    class SleepFunction:
        def __init__(self, timeFunction):
            self.timeFunction = timeFunction

        def __call__(self, delay):
            self.timeFunction.advance(delay)

    class TimeFunction:
        def __init__(self):
            self.now = 0.0

        def __call__(self):
            return self.now

        def advance(self, delay):
            self.now += delay

    class Handle:
        def __init__(self):
            self.answered = False

        def active(self):
            return not self.answered

        def answer(self):
            self.answered = True

    class AnswerTask(SchedulerTask):
        def __init__(self, handle):
            self.handle = handle

        def run(self):
            self.handle.answer()

    class NoOpTask(SchedulerTask):
        def run(self):
            pass

    def setUp(self):
        self.time = self.TimeFunction()
        self.sleep = self.SleepFunction(self.time)
        self.scheduler = Scheduler(self.sleep, self.time)
        self.poller = RequestPoller(self.scheduler)

    def test_wait_returns_empty_list_immediately_if_group_is_empty(self):
        ready = self.poller.wait()
        self.assertEqual(self.time(), 0.0)
        self.assertEqual(ready, [])

    def test_bool_returns_False_if_no_handles_are_registered(self):
        self.assertFalse(self.poller)

    def test_bool_returns_True_if_an_active_handle_is_registered(self):
        handle = self.Handle()
        self.poller.register(handle)
        self.assertTrue(handle.active())
        self.assertTrue(self.poller)

    def test_bool_returns_True_if_an_inactive_handle_is_registered(self):
        handle = self.Handle()
        handle.answer()
        self.poller.register(handle)
        self.assertFalse(handle.active())
        self.assertTrue(self.poller)

    def test_wait_returns_immediately_if_a_handle_is_already_ready(self):
        handle = self.Handle()
        self.poller.register(handle)
        handle.answer()
        self.poller.wait()
        self.assertEqual(self.time(), 0.0)

    def test_wait_returns_handle_after_it_receives_a_response(self):
        handle = self.Handle()
        self.scheduler.schedule(self.AnswerTask(handle), 1.25)
        self.poller.register(handle)
        ready = self.poller.wait()

        self.assertEqual(len(ready), 1)
        self.assertIn(handle, ready)
        self.assertEqual(self.time(), 1.25)

    def test_wait_only_returns_the_handle_that_is_ready(self):
        h1 = self.Handle()
        h2 = self.Handle()
        self.poller.register(h1)
        self.poller.register(h2)

        self.scheduler.schedule(self.AnswerTask(h2), 0.75)
        ready = self.poller.wait()
        self.assertEqual(len(ready), 1)
        self.assertIn(h2, ready)

    def test_wait_returns_all_handles_that_are_ready(self):
        h1 = self.Handle()
        h2 = self.Handle()
        h3 = self.Handle()
        self.poller.register(h1)
        self.poller.register(h2)
        self.poller.register(h3)

        self.scheduler.schedule(self.AnswerTask(h2), 0.75)
        self.scheduler.schedule(self.AnswerTask(h3), 0.75)

        ready = self.poller.wait()
        self.assertEqual(len(ready), 2)
        self.assertIn(h2, ready)
        self.assertIn(h3, ready)

    def test_wait_does_not_return_if_no_handles_are_ready(self):
        handle = self.Handle()
        self.poller.register(handle)

        self.scheduler.schedule(self.NoOpTask(), 1.0)
        self.scheduler.schedule(self.AnswerTask(handle), 2.0)

        ready = self.poller.wait()
        self.assertEqual(len(ready), 1)
        self.assertIn(handle, ready)
        self.assertEqual(self.time(), 2.0)

    def test_wait_returns_immediately_if_handles_are_already_ready(self):
        handle = self.Handle()
        self.poller.register(handle)

        self.scheduler.schedule(self.NoOpTask(), 0.5)
        handle.answer()

        ready = self.poller.wait()
        self.assertEqual(len(ready), 1)
        self.assertIn(handle, ready)
        self.assertEqual(self.time(), 0.0)

    def test_wait_does_not_return_the_same_handle_twice(self):
        h1 = self.Handle()
        h2 = self.Handle()

        self.poller.register(h1)
        self.poller.register(h2)

        self.scheduler.schedule(self.AnswerTask(h1), 0.75)
        self.scheduler.schedule(self.AnswerTask(h2), 0.5)

        ready = self.poller.wait()
        self.assertEqual(len(ready), 1)
        self.assertIn(h2, ready)
        self.assertEqual(self.time(), 0.5)

        ready = self.poller.wait()
        self.assertEqual(len(ready), 1)
        self.assertIn(h1, ready)
        self.assertEqual(self.time(), 0.75)

    def test_bool_returns_False_after_wait_returns_all_handles(self):
        h1 = self.Handle()
        h2 = self.Handle()

        self.poller.register(h1)
        self.poller.register(h2)

        self.scheduler.schedule(self.AnswerTask(h1), 1.0)
        self.scheduler.schedule(self.AnswerTask(h2), 2.0)

        ready = self.poller.wait()
        ready = self.poller.wait()
        self.assertFalse(self.poller)

    def test_wait_returns_handle_if_ready_before_timeout(self):
        handle = self.Handle()
        self.poller.register(handle)
        self.scheduler.schedule(self.AnswerTask(handle), 1.5)

        ready = self.poller.wait(2.0)
        self.assertEqual(len(ready), 1)
        self.assertIn(handle, ready)
        self.assertEqual(self.time(), 1.5)

    def test_wait_returns_empty_list_if_not_ready_before_timeout(self):
        handle = self.Handle()
        self.poller.register(handle)
        self.scheduler.schedule(self.AnswerTask(handle), 1.5)

        ready = self.poller.wait(1.0)
        self.assertEqual(ready, [])
        self.assertEqual(self.time(), 1.0)

if __name__ == "__main__":
    unittest.main()
