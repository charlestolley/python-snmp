__all__ = ['RWLock']

from threading import Lock

# returns a pair of objects, (r, w), which constitute a
# writer-preferred reader/writer lock
def RWLock():
    r = Lock()
    w = Lock()
    return RLock(r, w), WLock(r, w)


class ContextLock:
    def __enter__(self):
        self.acquire()

    def __exit__(self, *args, **kwargs):
        self.release()

class RLock(ContextLock):
    def __init__(self, r, w):
        self.r = r
        self.w = w
        self.mutex = Lock()
        self.queue = Lock()
        self.count = 0

    def acquire(self):
        with self.queue:
            with self.r:
                with self.mutex:
                    if not self.count:
                        self.w.acquire()
                    self.count += 1

    def release(self):
        with self.mutex:
            self.count -= 1
            if not self.count:
                self.w.release()

class WLock(ContextLock):
    def __init__(self, r, w):
        self.r = r
        self.w = w
        self.mutex = Lock()
        self.count = 0

    def acquire(self):
        with self.mutex:
            if not self.count:
                self.r.acquire()
            self.count += 1
        self.w.acquire()

    def release(self):
        self.w.release()
        with self.mutex:
            self.count -= 1
            if not self.count:
                self.r.release()
