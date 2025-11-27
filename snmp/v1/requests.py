__all__ = ["SNMPv1RequestAdmin"]

import weakref

from snmp.exception import *
from snmp.message import *
from snmp.pdu import *
from snmp.requests import *
from snmp.scheduler import *

pduTypes = {
    cls.TAG: cls for cls in (
        GetRequestPDU,
        GetNextRequestPDU,
        ResponsePDU,
        SetRequestPDU,
    )
}

class SNMPv1RequestHandle:
    def __init__(self, scheduler, request):
        self.callbacks = []
        self.future = scheduler.createFuture()
        self.request = request

    def __await__(self):
        return self.future.__await__()

    def __del__(self):
        if self.active():
            self.close()

    def active(self):
        return not self.future.done()

    def addCallback(self, callback, requestID):
        if self.active():
            self.callbacks.append((callback, requestID))
        else:
            callback(requestID)

    def close(self):
        while self.callbacks:
            callback, requestID = self.callbacks.pop()
            callback(requestID)

    def expire(self):
        if self.active():
            self.future.set_exception(Timeout())
            self.close()

    def push(self, message):
        if self.active():
            try:
                message.pdu.checkErrorStatus(self.request)
                self.request.checkResponse(message.pdu)
            except Exception as exc:
                self.future.set_exception(exc)
            else:
                self.future.set_result(message.pdu.variableBindings)

            self.close()

    def wait(self):
        return self.future.wait()

class SNMPv1RequestAdmin:
    class ExpireTask(SchedulerTask):
        def __init__(self, handle_ref):
            self.handle_ref = handle_ref

        def run(self):
            handle = self.handle_ref()
            if handle is not None:
                handle.expire()

    class SendTask(SchedulerTask):
        def __init__(self, handle_ref, channel, community):
            self.handle_ref = handle_ref
            self.channel = channel

            handle = self.handle_ref()
            if handle is not None:
                self.msg = Message(
                    ProtocolVersion.SNMPv1,
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

        handle = SNMPv1RequestHandle(self.scheduler, request)
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
