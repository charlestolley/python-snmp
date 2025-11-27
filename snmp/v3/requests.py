__all__ = ["MessageIDAuthority", "SNMPv3RequestHandle"]

import weakref

from snmp.exception import *
from snmp.numbers import *
from snmp.requests import *

class MessageIDAuthority(NumberAuthority):
    def newGenerator(self):
        return NumberGenerator(31, signed=False)

    class MessageIDAllocationFailure(SNMPLibraryBug):
        def __init__(self, attempts):
            errmsg = f"No available message ID found after {attempts} attempts"
            super().__init__(errmsg)

    class MessageIDDeallocationFailure(SNMPLibraryBug):
        def __init__(self, msgID: int):
            errmsg = f"Failed to release message ID {msgID}" \
                " because it is not currently reserved"
            super().__init__(errmsg)

    AllocationFailure = MessageIDAllocationFailure
    DeallocationFailure = MessageIDDeallocationFailure

class SNMPv3RequestHandle:
    def __init__(self, scheduler, pdu, *callbacks):
        self.callbacks = list(callbacks)
        self.exception = None
        self.future = scheduler.createFuture()
        self.pdu = pdu


    def __del__(self):
        if self.active():
            self.onDeactivate()

    @property
    def requestID(self):
        return self.pdu.requestID

    def active(self):
        return not self.future.done()

    def addCallback(self, callback):
        if self.active():
            self.callbacks.append(callback)
        else:
            callback(self.requestID)

    def onDeactivate(self):
        while self.callbacks:
            callback = self.callbacks.pop()
            callback(self.requestID)

    def expire(self):
        if self.active():
            if self.exception is None:
                self.exception = Timeout()

            self.future.set_exception(self.exception)
            self.onDeactivate()

    def push(self, response):
        if self.active():
            try:
                response.checkErrorStatus(self.pdu)
                self.pdu.checkResponse(response)
                self.future.set_result(response.variableBindings)
            except Exception as exc:
                self.future.set_exception(exc)

            self.onDeactivate()

    def report(self, exception):
        if self.active() and self.exception is None:
            self.exception = exception

    def wait(self):
        try:
            return self.future.wait()
        except KeyboardInterrupt as interrupt:
            if self.exception is not None:
                raise self.exception from interrupt
            else:
                raise
