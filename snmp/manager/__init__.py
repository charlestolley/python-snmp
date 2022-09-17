__all__ = ["Repeater", "Timeout"]

import math
import time
import weakref

from snmp.exception import *

class Timeout(SNMPException):
    pass

class Repeater:
    def __init__(self, request, period=1.0, timeout=10.0):
        now = time.time()

        self.expiration = now + timeout
        self.nextRefresh = now + period
        self.period = period
        self.request = weakref.ref(request)

    def __lt__(a, b):
        return a.target < b.target

    def start(self):
        now = time.time()
        self.nextRefresh = now + self.period
        return self.request()

    def refresh(self):
        request = self.request()
        if request is None or request.fulfilled:
            return None

        now = time.time()
        if self.expiration <= now:
            request.expired = True
            return 0.0

        delta = self.target - now

        if delta < 0:
            self.nextRefresh += math.ceil(-delta / self.period) * self.period
            request.send()

        return delta

    @property
    def target(self):
        return min(self.expiration, self.nextRefresh)
