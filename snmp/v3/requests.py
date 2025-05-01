__all__ = ["SNMPv3RequestDirector", "SNMPv3RequestSecretary"]

import weakref

from snmp.exception import *
from snmp.numbers import *
from snmp.pdu import *
from snmp.requests import *
from snmp.scheduler import *
from snmp.security import *
from snmp.smi import *
from snmp.v3.message import *

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

class SNMPv3RequestDirector:
    class DispatchTask(SchedulerTask):
        def __init__(self, secretary, args):
            self.cancelled = False
            self.secretary = secretary
            self.args = args

        def cancel(self):
            self.cancelled = True

        def run(self):
            if not self.cancelled:
                self.secretary.dispatch(*self.args)
                return self

    class ExpireTask(SchedulerTask):
        def __init__(self, handle):
            self.handle_reference = weakref.ref(handle)

        def run(self):
            handle = self.handle_reference()

            if handle is not None:
                handle.expire()

    def __init__(self, secretary, scheduler):
        self.scheduler = scheduler
        self.secretary = secretary

        self.requestIDAuthority = RequestIDAuthority()
        self.outstanding = weakref.WeakValueDictionary()
        self.handlers = {}
        self.tasks = {}

    def deliverReport(self, report, engineID, auth):
        try:
            handler = self.handlers[report.requestID]
            handle = self.outstanding[report.requestID]
        except KeyError:
            return

        exception = handler.processReport(report, engineID, auth)

        if exception is not None:
            handle.report(exception)

            if auth:
                handle.expire()

    def deliverResponse(self, response, engineID, auth):
        try:
            handler = self.handlers[response.requestID]
            handle = self.outstanding[response.requestID]
        except KeyError:
            return

        if handler.processResponse(response, engineID, auth):
            handle.push(response)

    def closeRequest(self, requestID):
        try:
            tasks = self.tasks.pop(requestID)
        except KeyError:
            pass
        else:
            for task in tasks.values():
                task.cancel()

        try:
            del self.handlers[requestID]
        except KeyError:
            pass

        try:
            del self.outstanding[requestID]
        except KeyError:
            pass

        self.requestIDAuthority.release(requestID)

    def openRequest(self, handler, timeout):
        handle = SNMPv3RequestHandle(
            self.scheduler,
            self.requestIDAuthority.reserve(),
            self.closeRequest,
        )

        self.outstanding[handle.requestID] = handle
        self.handlers[handle.requestID] = handler
        self.tasks[handle.requestID] = {}

        self.scheduler.schedule(self.ExpireTask(handle), timeout)

        return handle

    def resetRequest(self, requestID):
        try:
            tasks = self.tasks[requestID]
        except KeyError:
            return
        else:
            for task in tasks.values():
                task.cancel()

    def sendRequest(self,
        requestID,
        channel,
        engineID,
        pdu,
        contextName,
        securityLevel,
        userName,
        namespace,
        refreshPeriod,
    ):
        try:
            handle = self.outstanding[requestID]
        except KeyError:
            return None

        if handle.active():
            args = (
                channel,
                pdu.withRequestID(handle.requestID),
                engineID,
                contextName,
                securityLevel,
                userName,
                namespace,
                refreshPeriod,
            )

            dispatchTask = self.DispatchTask(self.secretary, args)

            if engineID in self.tasks[handle.requestID]:
                self.tasks[handle.requestID][engineID].cancel()

            self.tasks[handle.requestID][engineID] = dispatchTask
            self.scheduler.schedule(dispatchTask, period=refreshPeriod)

        return handle

class SNMPv3RequestSecretary:
    class CallbackTask(SchedulerTask):
        def __init__(self, function, *args):
            self.function = function
            self.args = args

        def run(self):
            self.function(*self.args)

    class MessageHandle:
        def __init__(self,
            requestID,
            engineID,
            contextName,
            securityLevel,
            userName,
            namespace,
        ):
            self.requestID = requestID
            self.engineID = engineID
            self.contextName = contextName
            self.securityLevel = securityLevel
            self.userName = userName
            self.namespace = namespace

    def __init__(self, sender, scheduler):
        self.director = None
        self.sender = sender
        self.scheduler = scheduler

        self.messageIDAuthority = MessageIDAuthority()
        self.messages = {}

    def expire(self, messageID):
        try:
            del self.messages[messageID]
        except KeyError:
            pass

        self.messageIDAuthority.release(messageID)

    def dispatch(self,
        channel,
        pdu,
        engineID,
        contextName,
        securityLevel,
        userName,
        namespace,
        timeout=0.0,
    ):
        messageID = self.messageIDAuthority.reserve()
        self.messages[messageID] = self.MessageHandle(
            pdu.requestID,
            engineID,
            contextName,
            securityLevel,
            userName,
            namespace,
        )

        expireTask = self.CallbackTask(self.expire, messageID)
        self.scheduler.schedule(expireTask, timeout)

        message = SNMPv3Message(
            HeaderData(
                messageID,
                1472,
                MessageFlags(securityLevel, True),
                SecurityModel.USM,
            ),
            ScopedPDU(pdu, engineID, contextName),
            engineID,
            SecurityName(userName, namespace),
        )

        self.sender.send(message, channel)

    def hear(self, message, channel):
        try:
            handle = self.messages[message.header.msgID]
        except KeyError:
            return

        if (handle.userName != message.securityName.userName
        or handle.contextName != message.scopedPDU.contextName):
            return

        if (message.header.flags.authFlag
        and handle.namespace not in message.securityName.namespaces):
            return

        if isinstance(message.scopedPDU.pdu, ReportPDU):
            self.director.deliverReport(
                message.scopedPDU.pdu.withRequestID(handle.requestID),
                message.securityEngineID,
                message.header.flags.authFlag,
            )
        elif isinstance(message.scopedPDU.pdu, ResponsePDU):
            if (message.header.flags.securityLevel < handle.securityLevel
            or  message.securityEngineID != handle.engineID
            or  message.scopedPDU.contextEngineID != handle.engineID
            or  message.scopedPDU.pdu.requestID != handle.requestID):
                return

            self.director.deliverResponse(
                message.scopedPDU.pdu,
                message.securityEngineID,
                message.header.flags.authFlag,
            )

    def reportTo(self, director):
        self.director = director
