__all__ = ["SNMPv2cRequestAdmin"]

import weakref

from snmp.exception import *
from snmp.message import *
from snmp.pdu import *
from snmp.requests import *
from snmp.scheduler import *
from snmp.typing import *

pduTypes = {
    cls.TAG: cls for cls in cast(Tuple[Type[AnyPDU], ...], (
        GetRequestPDU,
        GetNextRequestPDU,
        ResponsePDU,
        SetRequestPDU,
        GetBulkRequestPDU,
        InformRequestPDU,
        SNMPv2TrapPDU,
        ReportPDU,
    ))
}

class SNMPv2cRequestHandle:
    def __init__(self, scheduler, request):
        self.scheduler = scheduler
        self.callbacks = []

        self.request = request
        self.response = None

        self._expired = False

    def __del__(self):
        if self.active():
            self.close()

    def active(self):
        return self.response is None and not self.expired

    @property
    def expired(self):
        return self._expired

    @expired.setter
    def expired(self, expired):
        if expired and not self._expired:
            self._expired = True
            self.close()

    def close(self):
        while self.callbacks:
            callback, requestID = self.callbacks.pop()
            callback(requestID)

    def addCallback(self, callback, requestID):
        if self.active():
            self.callbacks.append((callback, requestID))
        else:
            callback(requestID)

    def push(self, message):
        if self.active():
            self.response = message.pdu
            self.close()

    def wait(self):
        while self.active():
            self.scheduler.wait()

        if self.response is not None:
            self.response.checkErrorStatus(self.request)
            vblist = self.response.variableBindings

            if not self.request.validResponse(vblist):
                raise ImproperResponse(vblist)
            else:
                return vblist
        else:
            raise Timeout()

class SNMPv2cRequestAdmin:
    class ExpireTask(SchedulerTask):
        def __init__(self, handle_ref):
            self.handle_ref = handle_ref

        def run(self):
            handle = self.handle_ref()
            if handle is not None:
                handle.expired = True

    class SendTask(SchedulerTask):
        def __init__(self, handle_ref, channel, community):
            self.handle_ref = handle_ref
            self.channel = channel

            handle = self.handle_ref()
            if handle is not None:
                self.msg = Message(
                    ProtocolVersion.SNMPv2c,
                    community,
                    handle.request,
                ).encode()

        def run(self):
            handle = self.handle_ref()
            if handle is not None and handle.active():
                self.channel.send(self.msg)
                return self

    def __init__(self, scheduler):
        self.requestIDAuthority = RequestIDAuthority()
        self.scheduler = scheduler
        self.outstanding = {}

    def closeRequest(self, requestID):
        try:
            del self.outstanding[requestID]
        except KeyError:
            pass

        self.requestIDAuthority.release(requestID)

    def openRequest(self, pdu, community, channel, timeout, refreshPeriod):
        requestID = self.requestIDAuthority.reserve()
        request = pdu.withRequestID(requestID)

        handle = SNMPv2cRequestHandle(self.scheduler, request)
        reference = weakref.ref(handle)
        self.outstanding[requestID] = reference, community
        handle.addCallback(self.closeRequest, requestID)

        expireTask = self.ExpireTask(reference)
        self.scheduler.schedule(expireTask, timeout)

        sendTask = self.SendTask(reference, channel, community)
        self.scheduler.schedule(sendTask, period=refreshPeriod)

        return handle

    def hear(self, data, channel):
        message = Message.decodeExact(data, types=pduTypes)

        try:
            reference, community = self.outstanding[message.pdu.requestID]
        except KeyError as err:
            errmsg = f"Unknown requestID: {message.pdu.requestID}"
            raise IncomingMessageError(errmsg)

        handle = reference()

        if handle is None:
            errmsg = f"Request {message.pdu.requestID} was not properly closed"
            raise SNMPLibraryBug(errmsg)

        if message.community != community:
            errmsg = "Wrong community name in response to" \
                f" request {message.pdu.requestID}:" \
                f" {message.community!r} != {community!r}"
            raise IncomingMessageError(errmsg)

        handle.push(message)
