__all__ = ["SchedulerTest"]

import gc
import unittest
import weakref

from snmp.scheduler import *

class SchedulerTest(unittest.TestCase):
    class CreepingTimeFunction:
        def __init__(self):
            self.count = 0
            self.now = 0.0

        def __call__(self):
            self.now += 0.25
            return self.now

        def advance(self, delay):
            self.now += delay

    class SleepFunction:
        def __init__(self, timeFunction):
            self.count = 0
            self.negativeDelayFound = False
            self.timeFunction = timeFunction

        def __call__(self, delay):
            if delay < 0.0:
                self.negativeDelayFound = True

            self.count += 1
            self.timeFunction.advance(delay)

    class TimeFunction:
        def __init__(self):
            self.now = 0.0

        def __call__(self):
            return self.now

        def advance(self, delay):
            self.now += delay

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
        self.timeFunction = self.TimeFunction()
        self.sleepFunction = self.SleepFunction(self.timeFunction)
        self.scheduler = Scheduler(self.sleepFunction, self.timeFunction)

    def test_task_with_no_delay_runs_before_schedule_returns(self):
        task = self.Task()
        self.scheduler.schedule(task)
        self.assertTrue(task.hasRun)

    def test_trywait_runs_task_if_ready(self):
        task = self.Task()

        self.scheduler.schedule(task, 0.5)
        self.sleepFunction(0.5)

        self.assertFalse(task.hasRun)
        self.scheduler.trywait()
        self.assertTrue(task.hasRun)

    def test_trywait_does_not_run_tasks_that_are_not_ready(self):
        task = self.Task()

        self.scheduler.schedule(task, 0.5)
        self.assertFalse(task.hasRun)
        self.scheduler.trywait()
        self.assertFalse(task.hasRun)

    def test_trywait_sleeps_0_if_task_is_ready(self):
        task = self.Task()

        self.scheduler.schedule(task, 0.5)
        self.sleepFunction(0.5)

        self.scheduler.trywait()
        self.assertEqual(self.timeFunction(), 0.5)
        self.assertEqual(self.sleepFunction.count, 2)

    def test_trywait_sleeps_0_when_nothing_is_ready(self):
        task = self.Task()

        self.scheduler.schedule(task, 0.5)

        self.scheduler.trywait()
        self.assertEqual(self.timeFunction(), 0.0)
        self.assertEqual(self.sleepFunction.count, 1)

    def test_wait_runs_task_once_its_ready(self):
        task = self.Task()

        self.scheduler.schedule(task, 0.5)
        self.assertFalse(task.hasRun)
        self.scheduler.wait()

        self.assertTrue(task.hasRun)
        self.assertEqual(self.timeFunction(), 0.5)

    def test_wait_sleeps_0_if_task_is_ready(self):
        task = self.Task()

        self.scheduler.schedule(task, 0.5)
        self.sleepFunction(0.5)
        self.scheduler.wait()

        self.assertTrue(task.hasRun)
        self.assertEqual(self.timeFunction(), 0.5)

    def test_wait_runs_the_soonest_task_regardless_of_schedule_order(self):
        t1 = self.Task()
        t2 = self.Task()

        self.scheduler.schedule(t1, 0.5)
        self.scheduler.schedule(t2, 0.25)
        self.scheduler.wait()

        self.assertFalse(t1.hasRun)
        self.assertTrue(t2.hasRun)
        self.assertEqual(self.sleepFunction.count, 1)
        self.assertEqual(self.timeFunction(), 0.25)

    def test_wait_calls_sleep_function_0_0_when_nothing_is_scheduled(self):
        self.scheduler.wait()
        self.assertEqual(self.sleepFunction.count, 1)
        self.assertEqual(self.timeFunction(), 0.0)

    def test_wait_never_calls_sleep_with_negative_argument(self):
        timeFunction = self.CreepingTimeFunction()
        sleepFunction = self.SleepFunction(timeFunction)
        scheduler = Scheduler(sleepFunction, timeFunction)

        t1 = self.Task()
        t2 = self.Task()

        # This test is very fragile, but at one time it did work
        # (meaning these delays caused the assertions to fail).
        scheduler.schedule(t1, 1.0)
        scheduler.schedule(t2, 0.375)
        scheduler.wait()

        self.assertTrue(t1.hasRun)
        self.assertTrue(t2.hasRun)
        self.assertFalse(sleepFunction.negativeDelayFound)

    def test_task_with_period_runs_the_returned_task(self):
        task = self.CopyTask()
        self.scheduler.schedule(task, period=1.0)
        self.assertTrue(task.hasRun)
        self.assertFalse(task.nextTask.hasRun)
        self.scheduler.wait()
        self.assertTrue(task.nextTask.hasRun)

    def test_task_with_period_repeats_until_it_returns_None(self):
        task = self.CountingTask()
        self.scheduler.schedule(task, period=1.0)
        self.assertEqual(task.count, 1)
        self.scheduler.wait()
        self.assertEqual(task.count, 2)
        self.scheduler.wait()
        self.assertEqual(task.count, 3)

        task.repeat = False
        self.scheduler.wait()
        self.assertEqual(task.count, 4)
        self.scheduler.wait()
        self.assertEqual(task.count, 4)

    def test_task_does_not_repeat_if_not_scheduled_with_period(self):
        task = self.CountingTask()
        self.scheduler.schedule(task)
        self.assertEqual(task.count, 1)
        self.scheduler.wait()
        self.assertEqual(task.count, 1)

    def test_task_object_reference_is_dropped_after_task_runs(self):
        task = self.Task()
        reference = weakref.ref(task)
        self.scheduler.schedule(task, 1.0)
        self.assertFalse(task.hasRun)

        del task
        gc.collect()

        self.assertIsNotNone(reference())
        self.scheduler.wait()
        gc.collect()
        self.assertIsNone(reference())

    def test_a_tasks_run_function_may_schedule_other_tasks(self):
        t1 = self.Task()
        t2 = self.ScheduleTask(self.scheduler, t1, 1.0)

        self.scheduler.schedule(t2)
        self.assertFalse(t1.hasRun)

        self.scheduler.wait()
        self.assertTrue(t1.hasRun)

if __name__ == "__main__":
    unittest.main()
