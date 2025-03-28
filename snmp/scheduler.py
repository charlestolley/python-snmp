__all__ = ["Scheduler", "SchedulerTask"]

import heapq
import time

from snmp.typing import *

class SchedulerTask:
    def run(self) -> Optional["SchedulerTask"]:
        raise NotImplementedError()

class SchedulerEntry:
    def __init__(self,
        task: SchedulerTask,
        timestamp: float,
        period: Optional[float],
    ):
        if period is not None and period <= 0.0:
            raise ValueError("A repeated task must have a positive period")

        self.task = task
        self.timestamp = timestamp
        self.period = period

    def __call__(self) -> Optional["SchedulerEntry"]:
        nextTask = self.task.run()

        if nextTask is None or self.period is None:
            return None

        nextTime = self.timestamp + self.period
        return self.__class__(nextTask, nextTime, self.period)

    def __lt__(self, other: "SchedulerEntry") -> bool:
        return self.timestamp < other.timestamp

    def ready(self, timestamp: float) -> bool:
        return self.timeToReady(timestamp) <= 0

    def timeToReady(self, timestamp: float) -> float:
        return self.timestamp - timestamp

class Scheduler:
    class ReEntrancyLock:
        def __init__(self):
            self.locked = False

        def __enter__(self):
            self.locked = True

        def __exit__(self, *args, **kwargs):
            self.locked = False

    def __init__(self,
        sleep_function: Callable[[float], None] = time.sleep,
        time_function: Callable[[], float] = time.time,
    ) -> None:
        self.lock = self.ReEntrancyLock()
        self.sleep = sleep_function
        self.time = time_function
        self.upcoming: List[SchedulerEntry] = []

    def runPendingTasks(self) -> None:
        if self.lock.locked:
            return

        with self.lock:
            while self.upcoming and self.upcoming[0].ready(self.time()):
                nextEntry = self.upcoming[0]()

                if nextEntry is None:
                    heapq.heappop(self.upcoming)
                else:
                    heapq.heapreplace(self.upcoming, nextEntry)

    def schedule(self,
        task: SchedulerTask,
        delay: float = 0.0,
        period: Optional[float] = None,
    ) -> None:
        now = self.time()
        entry = SchedulerEntry(task, now + delay, period)
        heapq.heappush(self.upcoming, entry)
        self.runPendingTasks()

    def wait(self) -> None:
        if self.upcoming:
            now = self.time()
            entry = self.upcoming[0]
            waitTime = max(entry.timeToReady(now), 0.0)
        else:
            waitTime = 0.0

        self.sleep(waitTime)
        self.runPendingTasks()
