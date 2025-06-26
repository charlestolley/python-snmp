__all__ = ["ImproperResponse", "MessageIDAuthority", "SNMPv3RequestHandle"]

import weakref

from snmp.exception import *
from snmp.numbers import *
from snmp.pdu import *
from snmp.requests import *

class ImproperResponse(SNMPException):
    def __init__(self, variableBindings):
        self.variableBindings = variableBindings

class MessageIDAuthority(NumberAuthority):
    def newGenerator(self):
        return NumberGenerator(31, signed=False)

    class MessageIDAllocationFailure(SNMPLibraryBug): pass
    class MessageIDDeallocationFailure(SNMPLibraryBug): pass

    AllocationFailure = MessageIDAllocationFailure
    DeallocationFailure = MessageIDDeallocationFailure

class SNMPv3RequestHandle:
    def __init__(self, scheduler, pdu, *callbacks):
        self.callbacks = list(callbacks)
        self.pdu = pdu
        self.scheduler = scheduler

        self.response = None
        self.exception = None
        self.expired = False

    def __del__(self):
        if self.active():
            self.onDeactivate()

    @property
    def requestID(self) -> int:
        return self.pdu.requestID

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
                    self.pdu,
                )

            vblist = self.response.variableBindings

            if not self.pdu.validResponse(vblist):
                raise ImproperResponse(vblist)
            else:
                return vblist
        elif self.exception is not None:
            raise self.exception
        else:
            assert self.expired
            raise Timeout()
