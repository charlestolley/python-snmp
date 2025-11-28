__all__ = ["AsyncMultiplexorTest", "AsyncSchedulerTest"]

import gc
import unittest
import weakref

from snmp.async_engine import AsyncMultiplexor, AsyncScheduler
from snmp.scheduler import *

class AsyncSchedulerTest(unittest.TestCase):
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

    class SchedulerLoop:
        class Task(SchedulerTask):
            def __init__(self, callback, *args):
                self.callback = callback
                self.args = args

            def run(self):
                self.callback(*self.args)

        def __init__(self, sleepFunction, timeFunction):
            self.scheduler = Scheduler(sleepFunction, timeFunction)

        def call_soon(self, callback, *args):
            return self.call_later(0.0, callback, *args)

        def call_later(self, delay, callback, *args):
            task = self.Task(callback, *args)
            self.scheduler.schedule(task, delay)

        def run(self):
            self.scheduler.wait()

    class CopyTask(SchedulerTask):
        def __init__(self):
            self.nextTask = None

        @property
        def hasRun(self):
            return self.nextTask is not None

        def run(self):
            self.nextTask = self.__class__()
            return self.nextTask

    class CountingTask(SchedulerTask):
        def __init__(self):
            self.count = 0
            self.repeat = True

        def run(self):
            self.count += 1

            if self.repeat:
                return self

    class ScheduleTask(SchedulerTask):
        def __init__(self, scheduler, task, *args, **kwargs):
            self.scheduler = scheduler
            self.task = task
            self.args = args
            self.kwargs = kwargs

        def run(self):
            self.scheduler.schedule(self.task, *self.args, **self.kwargs)

    class Task(SchedulerTask):
        def __init__(self):
            self.hasRun = False

        def run(self):
            self.hasRun = True

    def setUp(self):
        self.time = self.TimeFunction()
        self.sleep = self.SleepFunction(self.time)
        self.loop = self.SchedulerLoop(self.sleep, self.time)

        self.scheduler = AsyncScheduler(self.loop)

    def test_task_with_no_delay_runs_before_schedule_returns(self):
        task = self.Task()
        self.scheduler.schedule(task)
        self.assertTrue(task.hasRun)

    def test_delayed_task_runs_at_the_scheduled_time(self):
        task = self.Task()

        self.scheduler.schedule(task, 0.5)
        self.assertFalse(task.hasRun)
        self.loop.run()

        self.assertTrue(task.hasRun)
        self.assertEqual(self.time(), 0.5)

    def test_task_with_period_runs_the_returned_task(self):
        period = 1.75
        task = self.CopyTask()
        self.scheduler.schedule(task, period=period)
        self.assertTrue(task.hasRun)

        for i in range(5):
            task = task.nextTask
            self.assertFalse(task.hasRun)
            self.loop.run()
            self.assertTrue(task.hasRun)
            self.assertEqual(self.time(), (i+1) * period)

    def test_task_with_period_repeats_until_it_returns_None(self):
        task = self.CountingTask()
        self.scheduler.schedule(task, period=1.0)
        self.assertEqual(task.count, 1)
        self.loop.run()
        self.assertEqual(task.count, 2)
        self.loop.run()
        self.assertEqual(task.count, 3)

        task.repeat = False
        self.loop.run()
        self.assertEqual(task.count, 4)
        self.loop.run()
        self.assertEqual(task.count, 4)

    def test_task_does_not_repeat_if_not_scheduled_with_period(self):
        task = self.CountingTask()
        self.scheduler.schedule(task)
        self.assertEqual(task.count, 1)
        self.loop.run()
        self.assertEqual(task.count, 1)

    def test_task_object_reference_is_dropped_after_task_runs(self):
        task = self.Task()
        reference = weakref.ref(task)
        self.scheduler.schedule(task, 1.0)
        self.assertFalse(task.hasRun)

        del task
        gc.collect()

        self.assertIsNotNone(reference())
        self.loop.run()
        gc.collect()
        self.assertIsNone(reference())

    def test_a_tasks_run_function_may_schedule_other_tasks(self):
        t1 = self.Task()
        t2 = self.ScheduleTask(self.scheduler, t1, 1.0)

        self.scheduler.schedule(t2)
        self.assertFalse(t1.hasRun)

        self.loop.run()
        self.assertTrue(t1.hasRun)

    def test_createFuture_returns_the_result_of_create_future(self):
        class Loop:
            def create_future(self):
                return 174

        scheduler = AsyncScheduler(Loop())
        self.assertEqual(scheduler.createFuture(), 174)

class AsyncMultiplexorTest(unittest.TestCase):
    class Socket:
        def __init__(self, fileno, addr, data):
            self.addr = addr
            self.data = data
            self.fileno = fileno

        def receive(self):
            return self.addr, self.data

    class Loop:
        def __init__(self):
            self.callbacks = {}

        def add_reader(self, fileno, callback, *args):
            self.callbacks[fileno] = callback, args

        def remove_reader(self, fileno):
            del self.callbacks[fileno]

        def ready(self, fileno):
            callback, args = self.callbacks[fileno]
            callback(*args)

    class Listener:
        def __init__(self):
            self.channel = None
            self.message = None

        def hear(self, message, channel):
            self.message = message
            self.channel = channel

    def setUp(self):
        self.loop = self.Loop()
        self.mux = AsyncMultiplexor(self.loop)

    def test_register_adds_reader(self):
        sock = self.Socket(45, "1.2.3.4", b"test message")
        listener = self.Listener()
        self.mux.register(sock, listener)
        self.loop.ready(45)

        self.assertEqual(listener.message, b"test message")
        self.assertEqual(listener.channel.address, "1.2.3.4")
        self.assertIs(listener.channel.transport, sock)

    def test_close_unregisters_all_readers(self):
        s1 = self.Socket(55, "::", b"IPv6")
        s2 = self.Socket(56, "555 N Main St.", b"Mailing")
        s3 = self.Socket(57, "me@example.com", b"E-mail")

        listener = self.Listener()
        self.mux.register(s1, listener)
        self.mux.register(s2, listener)
        self.mux.register(s3, listener)

        self.loop.ready(55)
        self.loop.ready(56)
        self.loop.ready(57)

        self.mux.close()

        self.assertRaises(KeyError, self.loop.ready, 55)
        self.assertRaises(KeyError, self.loop.ready, 56)
        self.assertRaises(KeyError, self.loop.ready, 57)

if __name__ == "__main__":
    unittest.main()
