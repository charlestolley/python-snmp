__all__ = []

import weakref

from snmp.exception import *
from snmp.numbers import *
from snmp.pdu import *
from snmp.requests import *

class MessageIDAuthority(NumberAuthority):
    def newGenerator(self):
        return NumberGenerator(31, signed=False)

    class MessageIDAllocationFailure(SNMPLibraryBug): pass
    class MessageIDDeallocationFailure(SNMPLibraryBug): pass

    AllocationFailure = MessageIDAllocationFailure
    DeallocationFailure = MessageIDDeallocationFailure

class SNMPv3RequestHandle:
    def __init__(self, scheduler, requestID, *callbacks):
        self.callbacks = list(callbacks)
        self.requestID = requestID
        self.scheduler = scheduler

        self.response = None
        self.exception = None
        self.expired = False

    def __del__(self):
        if self.active():
            self.onDeactivate()

    def addCallback(self, callback):
        if self.active():
            self.callbacks.append(callback)
        else:
            callback(self.requestID)

    def onDeactivate(self):
        while self.callbacks:
            callback = self.callbacks.pop()
            callback(self.requestID)

    def active(self):
        return self.response is None and not self.expired

    def expire(self):
        if self.active():
            self.expired = True
            self.onDeactivate()

    def push(self, response):
        if self.active():
            self.response = response
            assert self.response is not None
            self.onDeactivate()

    def report(self, exception):
        if self.active() and self.exception is None:
            self.exception = exception

    def wait(self):
        while self.active():
            try:
                self.scheduler.wait()
            except KeyboardInterrupt as interrupt:
                if self.exception is not None:
                    raise self.exception from interrupt
                else:
                    raise

        if self.response is not None:
            if self.response.errorStatus:
                raise ErrorResponse(
                    self.response.errorStatus,
                    self.response.errorIndex,
                    self.response.variableBindings,
                )
            else:
                return self.response.variableBindings
        elif self.exception is not None:
            raise self.exception
        else:
            assert self.expired
            raise Timeout()
