__all__ = ["Scheduler", "SchedulerTask"]

import heapq
import time

class SchedulerTask:
    def run(self):
        raise NotImplementedError()

class Future:
    def __init__(self, scheduler):
        self._result = None
        self._exception = None
        self.scheduler = scheduler

    def done(self):
        return self._result is not None or self._exception is not None

    def set_result(self, result):
        self._result = result

    def set_exception(self, exc):
        self._exception = exc

    def result(self):
        if self._result is not None:
            return self._result
        elif self._exception is not None:
            raise self._exception
        else:
            return None

    def wait(self):
        while not self.done():
            self.scheduler.wait()

        return self.result()

class SchedulerEntry:
    def __init__(self, task, timestamp, period):
        if period is not None and period <= 0.0:
            raise ValueError("A repeated task must have a positive period")

        self.task = task
        self.timestamp = timestamp
        self.period = period

    def __call__(self):
        nextTask = self.task.run()

        if nextTask is None or self.period is None:
            return None

        nextTime = self.timestamp + self.period
        return self.__class__(nextTask, nextTime, self.period)

    def __lt__(self, other):
        return self.timestamp < other.timestamp

    def ready(self, timestamp):
        return self.timeToReady(timestamp) <= 0

    def timeToReady(self, timestamp):
        return self.timestamp - timestamp

class Scheduler:
    class ReEntrancyLock:
        def __init__(self):
            self.locked = False

        def __enter__(self):
            self.locked = True

        def __exit__(self, *args, **kwargs):
            self.locked = False

    def __init__(self, sleep_function = time.sleep, time_function = time.time):
        self.lock = self.ReEntrancyLock()
        self.sleep = sleep_function
        self.time = time_function
        self.upcoming = []

    def createFuture(self):
        return Future(self)

    def runPendingTasks(self):
        if self.lock.locked:
            return

        with self.lock:
            while self.upcoming and self.upcoming[0].ready(self.time()):
                nextEntry = self.upcoming[0]()

                if nextEntry is None:
                    heapq.heappop(self.upcoming)
                else:
                    heapq.heapreplace(self.upcoming, nextEntry)

    def schedule(self, task, delay = 0.0, period = None):
        now = self.time()
        entry = SchedulerEntry(task, now + delay, period)
        heapq.heappush(self.upcoming, entry)
        self.runPendingTasks()

    def trywait(self):
        self.sleep(0.0)
        self.runPendingTasks()

    def wait(self):
        if self.upcoming:
            now = self.time()
            entry = self.upcoming[0]
            waitTime = max(entry.timeToReady(now), 0.0)
        else:
            waitTime = 0.0

        self.sleep(waitTime)
        self.runPendingTasks()
