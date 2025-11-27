__all__ = ["AsyncEngine"]

import asyncio

from snmp.engine import GenericEngine
from snmp.transport import TransportMultiplexor
from snmp.utils import forbidKeywordArgument

class AsyncScheduler:
    def __init__(self, loop):
        self.loop = loop

    def createFuture(self):
        return self.loop.create_future()

    def schedule(self, task, delay = 0.0, period = None):
        def callback():
            nextTask = task.run()
            if nextTask is not None and period is not None:
                self.loop.call_later(period, callback)

        args = ()
        if delay == 0.0:
            self.loop.call_soon(callback)
        else:
            self.loop.call_later(delay, callback)

class AsyncMultiplexor(TransportMultiplexor):
    def __init__(self, loop):
        self.loop = loop
        self.readers = set()

    def close(self):
        for fd in self.readers:
            self.loop.remove_reader(fd)

        self.readers.clear()

    def register(self, transport, listener):
        self.readers.add(transport.fileno)
        self.loop.add_reader(
            transport.fileno,
            self.receive,
            transport,
            listener,
        )

class AsyncManager:
    def __init__(self, manager):
        self.manager = manager

    async def get(self, *args, **kwargs):
        forbidKeywordArgument("get", "wait", kwargs)
        handle = self.manager.get(*args, **kwargs)
        return await handle

    async def getBulk(self, *args, **kwargs):
        forbidKeywordArgument("getBulk", "wait", kwargs)
        handle = self.manager.getBulk(*args, **kwargs)
        return await handle

    async def getNext(self, *args, **kwargs):
        forbidKeywordArgument("getNext", "wait", kwargs)
        handle = self.manager.getNext(*args, **kwargs)
        return await handle

    async def set(self, *args, **kwargs):
        forbidKeywordArgument("set", "wait", kwargs)
        handle = self.manager.set(*args, **kwargs)
        return await handle

class AsyncEngine(GenericEngine):
    def __init__(self, *args, **kwargs):
        forbidKeywordArgument("__init__", "autowait", kwargs)
        loop = asyncio.get_event_loop()

        super().__init__(
            AsyncMultiplexor(loop),
            AsyncScheduler(loop),
            *args,
            autowait=False,
            **kwargs,
        )

    def Manager(self, *args, **kwargs):
        forbidKeywordArgument("Manager", "autowait", kwargs)
        manager = super().Manager(*args, **kwargs)
        return AsyncManager(manager)
