__all__ = ["RequestIDAuthorityTest", "RequestPollerTest"]

import heapq
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
            self.handles = []
            self.timeFunction = timeFunction

        def __call__(self, delay, poll=True):
            if (poll
            and self.handles
            and self.handles[0][0] <= self.timeFunction() + delay):
                wake_time, handle = heapq.heappop(self.handles)
                delay = wake_time - self.timeFunction()

                if delay >= 0.0:
                    self.timeFunction.advance(delay)

                handle.answer()
            else:
                self.timeFunction.advance(delay)

        def register(self, handle, delay=0.0):
            wake_time = self.timeFunction() + delay
            heapq.heappush(self.handles, (wake_time, handle))

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

    # This is a meta-test to make sure the helper SleepFunction works properly
    def test_SleepFunction_answers_registered_handle_at_the_right_time(self):
        h1 = self.Handle()
        h2 = self.Handle()

        self.poller.register(h1)
        self.poller.register(h2)

        self.sleep.register(h1, 7/8)
        self.sleep.register(h2, 1/4)

        # poll=False simulates the passage of time; the default is True
        # so that it answers the handles when called by the scheduler
        self.sleep(3/8, poll=False)
        self.assertEqual(self.time(), 3/8)
        self.assertTrue(h2.active())

        ready = self.poller.wait(1.0)
        self.assertEqual(len(ready), 1)
        self.assertIn(h2, ready)
        self.assertEqual(self.time(), 3/8)

        ready = self.poller.wait(1.0)
        self.assertEqual(len(ready), 1)
        self.assertIn(h1, ready)
        self.assertEqual(self.time(), 7/8)

    def test_poller_calls_scheduler_wait_when_timeout_is_zero(self):
        h1 = self.Handle()
        h2 = self.Handle()

        self.poller.register(h1)
        self.poller.register(h2)

        self.sleep.register(h1, 3/8)
        self.sleep.register(h2, 5/8)

        ready = self.poller.wait(0.0)
        self.assertEqual(len(ready), 0)
        self.assertEqual(self.time(), 0.0)

        self.sleep(3/8, poll=False)
        self.assertTrue(h1.active())

        ready = self.poller.wait(0.0)
        self.assertEqual(self.time(), 3/8)
        self.assertEqual(len(ready), 1)
        self.assertIn(h1, ready)

        self.sleep(1/4, poll=False)
        self.assertTrue(h2.active())

        ready = self.poller.wait(0.0)
        self.assertEqual(self.time(), 5/8)
        self.assertEqual(len(ready), 1)
        self.assertIn(h2, ready)

if __name__ == "__main__":
    unittest.main()
