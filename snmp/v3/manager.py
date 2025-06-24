__all__ = [
    "RequestError",
    "AuthenticationFailure", "PrivacyFailure", "TimeWindowFailure",
    "UnknownUserName", "UnsupportedSecurityLevel", "UnhandledReport",
    "InvalidResponseField", "NamespaceMismatch",
]

import collections
import re
import weakref

from snmp.exception import *
from snmp.pdu import *
from snmp.scheduler import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.usm.stats import *
from snmp.smi import *
from snmp.requests import *
from snmp.v3.message import *
from snmp.v3.requests import MessageIDAuthority, SNMPv3RequestHandle
from snmp.utils import typename

class RequestError(SNMPException):
    pass

class AuthenticationFailure(RequestError):
    def __init__(self, user):
        errmsg = "The remote engine reports an invalid message signature." \
            f" Check that user \"{user}\" is configured to use the right" \
            " authentication protocol and secret."

        super().__init__(errmsg)

class PrivacyFailure(RequestError):
    def __init__(self, user):
        errmsg = "The remote engine was unable to decrypt this request." \
            f" Check that user \"{user}\" is configured to use the right" \
            " privacy protocol and secret."

        super().__init__(errmsg)

class TimeWindowFailure(RequestError):
    def __init__(self):
        errmsg = "The remote engine has replied with multiple" \
            " NotInTimeWindow reports. It may be necessary to manually" \
            " reconfigure the remote engine with a new engine ID."

        super().__init__(errmsg)

class UnknownUserName(RequestError):
    def __init__(self, user):
        errmsg = f"The remote engine does not recognize user \"{user}\"."
        super().__init__(errmsg)

class UnsupportedSecurityLevel(RequestError):
    def __init__(self, user, securityLevel):
        errmsg = "The remote engine reports that user" \
            f" \"{user}\" does not support {securityLevel}."

        super().__init__(errmsg)

class UnhandledReport(RequestError):
    def __init__(self, varbind):
        self.report = varbind
        errmsg = "The remote engine raised a report that the manager" \
            f" does not know how to handle: {varbind}"
        super().__init__()

class InvalidResponseField(IncomingMessageError):
    def __init__(self, field_name, response_value, request_value):
        errmsg = f"The {field_name} of the response ({response_value})" \
            f" did not match the request ({request_value})."
        super().__init__(errmsg)

class NamespaceMismatch(IncomingMessageError):
    def __init__(self, matched, expected):
        # Use double quotes (default string formatting uses single quotes)
        matched_string = "[\"" + "\", \"".join(matched) + "\"]"

        errmsg = f"The response message was successfully authenticated," \
            f" but not under the expected namespace (\"{expected}\")." \
            f" Matched namespace(s): {matched_string}"
        super().__init__(errmsg)

class Thingy:
    def __init__(self):
        self.authority = MessageIDAuthority()
        self.handlers = {}

    def hear(self, message, channel):
        messageID = message.header.msgID

        try:
            listener = self.handlers[messageID]
        except KeyError:
            raise IncomingMessageError(f"Unknown message ID: {messageID}")

        listener.hear(message)

    def reserveMessageID(self, listener):
        messageID = self.authority.reserve()
        self.handlers[messageID] = listener
        return messageID

    def releaseMessageID(self, messageID):
        try:
            del self.handlers[messageID]
        except KeyError:
            pass

        self.authority.release(messageID)

class DiscoveryHandler:
    class RefreshTask(SchedulerTask):
        def __init__(self, handler):
            self.cancelled = False
            self.handler = handler

        def cancel(self):
            self.cancelled = True

        def run(self):
            if not self.cancelled:
                self.handler.expireMessage()
                self.handler.sendNewMessage()
                self.handler.scheduleRefresh()

    def __init__(self, handle, callback, scheduler, thingy, sender, channel):
        self.channel = channel
        self.sender = sender
        self.scheduler = scheduler
        self.thingy = thingy

        self.messageID = 0
        self.refreshTask = None
        self.unsent = collections.OrderedDict()

        self.callback = callback

        self.handle = handle
        self.handle.addCallback(self.onHandleDeactivate)

    def hear(self, message):
        self.stopDiscovery()
        self.callback(message.securityEngineID)

    def expireMessage(self):
        self.thingy.releaseMessageID(self.messageID)

    def sendNewMessage(self):
        self.messageID = self.thingy.reserveMessageID(self)

        message = SNMPv3Message(
            HeaderData(
                self.messageID,
                1472,
                MessageFlags(reportable=True),
                SecurityModel.USM,
            ),
            ScopedPDU(GetRequestPDU(requestID=self.handle.requestID), b""),
            b"",
            SecurityName(b""),
        )

        self.sender.send(message, self.channel)

    def scheduleRefresh(self, delay=None):
        if delay is None:
            delay = next(iter(self.unsent.values()))

        self.refreshTask = self.RefreshTask(self)
        self.scheduler.schedule(self.refreshTask, delay)

    def dropRequest(self, requestID):
        del self.unsent[requestID]

        if not self.unsent:
            self.stopDiscovery()
            return True
        else:
            return False

    def saveRequest(self, requestID, refreshPeriod):
        self.unsent[requestID] = refreshPeriod

        if self.refreshTask is None:
            self.sendNewMessage()
            self.scheduleRefresh(refreshPeriod)

    def stopDiscovery(self):
        if self.refreshTask is not None:
            self.refreshTask.cancel()
            self.refreshTask = None
            self.expireMessage()

    def onHandleDeactivate(self, requestID):
        self.stopDiscovery()

class SNMPv3Manager3:
    class ExpireTask(SchedulerTask):
        def __init__(self, handle):
            self.handle_ref = weakref.ref(handle)

        def run(self):
            handle = self.handle_ref()

            if handle is not None:
                handle.expire()

    class RequestState:
        class SendTask(SchedulerTask):
            def __init__(self, handle, engineID, manager):
                self.cancelled = False
                self.exception = False
                self.messageID = 0

                self.engineID = engineID
                self.handle_ref = weakref.ref(handle)
                self.manager = manager

            def cancel(self):
                self.cancelled = True

            def raiseException(self):
                self.exception = True

            def run(self):
                if self.messageID != 0:
                    self.manager.deallocateMessage(self.messageID)
                    self.messageID = 0

                if self.cancelled:
                    return None

                handle = self.handle_ref()

                if handle is None or not handle.active():
                    return None

                if self.exception:
                    handle.expire()
                    return None

                self.messageID = self.manager.allocateMessage(handle.requestID, self.engineID)

                message = self.manager.requests[handle.requestID].message \
                    .withMessageID(self.messageID) \
                    .withEngineID(self.engineID)

                self.manager.sender.send(message, self.manager.channel)
                return self

        def __init__(self, handle, message, refreshPeriod):
            self.handle_ref = weakref.ref(handle)
            self.message = message
            self.refreshPeriod = refreshPeriod

            self.cancelled = {}
            self.tasks = {}

        @property
        def handle(self):
            handle = self.handle_ref()

            if handle is None:
                raise SNMPLibraryBug("Request State was not dropped"
                    " when the request handle deactivated")

            return handle

        def cancel(self, engineID):
            if engineID in self.cancelled:
                return False

            task = self.tasks.pop(engineID)
            task.cancel()
            self.cancelled[engineID] = task
            return True

        def expireOnRefresh(self, engineID):
            self.tasks[engineID].raiseException()

        def resend(self, engineID, manager):
            if engineID in self.tasks:
                self.tasks[engineID].cancel()
                del self.tasks[engineID]

            self.send(engineID, manager)

        def select(self, engineID):
            for taskEngineID, task in self.tasks.items():
                if taskEngineID != engineID:
                    task.cancel()

        def send(self, engineID, manager):
            if engineID in self.tasks:
                return

            sendTask = self.SendTask(self.handle, engineID, manager)
            manager.scheduler.schedule(sendTask, period=self.refreshPeriod)
            self.tasks[engineID] = sendTask

    def __init__(self,
        scheduler,
        thingy,
        sender,
        channel,
        namespace,
        defaultUserName,
        defaultSecurityLevel,
        engineID,
        autowait,
    ):
        self.channel = channel
        self.sender = sender
        self.thingy = thingy

        self.engineIDAuthenticated = False
        self.engineID = engineID
        self.namespace = namespace

        self.autowait = autowait
        self.defaultUserName = defaultUserName
        self.defaultSecurityLevel = defaultSecurityLevel

        self.scheduler = scheduler
        self.requestIDAuthority = RequestIDAuthority()

        self.discovery = None

        self.mapping = {}
        self.requests = {}

    byteStringRegex = re.compile(r"b\'(.*)\'")
    def decodeUserName(self, userName):
        try:
            return userName.decode()
        except UnicodeDecodeError:
            pass

        representation = repr(userName)
        match = re.match(self.byteStringRegex, representation)

        if match is not None:
            return match.group(1)
        else:
            return representation

    def openRequestNoTimeout(self, *callbacks):
        handle = SNMPv3RequestHandle(
            self.scheduler,
            self.requestIDAuthority.reserve(),
            self.requestIDAuthority.release,
            *callbacks,
        )

        return handle

    def openRequest(self, timeout, *callbacks):
        handle = self.openRequestNoTimeout(*callbacks)
        expireTask = self.ExpireTask(handle)
        self.scheduler.schedule(expireTask, timeout)
        return handle

    def onRequestClosed(self, requestID):
        if self.engineID is None and self.discovery is not None:
            if self.discovery.dropRequest(requestID):
                self.discovery = None
        else:
            del self.requests[requestID]

    def setEngineID(self, engineID, auth):
        if self.engineIDAuthenticated and not auth:
            return

        if auth and not self.engineIDAuthenticated:
            self.engineIDAuthenticated = True

        if engineID == self.engineID:
            return

        oldEngineID = self.engineID
        self.engineID = engineID

        for request in self.requests.values():
            request.select(engineID)
            request.send(engineID, self)

    def discoveryCallback(self, engineID):
        self.discovery = None
        self.setEngineID(engineID, False)

    def allocateMessage(self, requestID, engineID):
        messageID = self.thingy.reserveMessageID(self)
        self.mapping[messageID] = requestID, engineID
        return messageID

    def deallocateMessage(self, messageID):
        del self.mapping[messageID]
        self.thingy.releaseMessageID(messageID)

    def hear(self, message):
        messageID = message.header.msgID

        try:
            requestID, engineID = self.mapping[messageID]
        except KeyError as err:
            errmsg = f"RequestID not found for message {messageID}"
            raise SNMPLibraryBug(errmsg) from err

        try:
            requestState = self.requests[requestID]
        except KeyError as err:
            errmsg = f"Request {requestID} is no longer active"
            raise IncomingMessageError(errmsg) from err

        handle = requestState.handle
        requestMessage = requestState.message

        pdu = message.scopedPDU.pdu
        if pdu.INTERNAL_CLASS:
            if pdu.requestID != 0 and pdu.requestID != requestID:
                raise IncomingMessageError("ReportPDU has the wrong requestID")
            elif message.scopedPDU.contextName != b"" and message.scopedPDU.contextName != requestMessage.scopedPDU.contextName:
                raise IncomingMessageError("Report message has the wrong contextName")

            if len(pdu.variableBindings) < 1:
                raise IncomingMessageError("No OIDs in report")

            oid = pdu.variableBindings[0].name
            if oid == usmStatsUnknownEngineIDsInstance:
                requestState.send(message.securityEngineID, self)
            elif message.securityEngineID != engineID:
                raise IncomingMessageError("Engine ID does not match the request")
            elif oid == usmStatsNotInTimeWindowsInstance:
                if requestMessage.header.flags.authFlag:
                    refreshPeriod = requestState.refreshPeriod
                    cancelled = requestState.cancel(engineID)

                    if cancelled:
                        requestState.resend(engineID, self)
                    else:
                        handle.report(TimeWindowFailure())
                        if message.header.flags.authFlag:
                            handle.expire()
                        else:
                            requestState.expireOnRefresh(engineID)
            elif oid == usmStatsUnsupportedSecLevelsInstance:
                requestSecLevel = requestMessage.header.flags.securityLevel
                reportSecLevel = message.header.flags.securityLevel

                if reportSecLevel < requestSecLevel:
                    userName = requestMessage.securityName.userName
                    user = self.decodeUserName(userName)
                    error = UnsupportedSecurityLevel(user, requestSecLevel)
                    handle.report(error)

                    if message.header.flags.authFlag:
                        handle.expire()
                    else:
                        requestState.expireOnRefresh(engineID)
            elif oid == usmStatsUnknownUserNamesInstance:
                if not message.header.flags.authFlag:
                    userName = requestMessage.securityName.userName
                    user = self.decodeUserName(userName)
                    handle.report(UnknownUserName(user))
                    requestState.expireOnRefresh(engineID)
            elif oid == usmStatsWrongDigestsInstance:
                if requestMessage.header.flags.authFlag:
                    userName = requestMessage.securityName.userName
                    user = self.decodeUserName(userName)
                    handle.report(AuthenticationFailure(user))
                    requestState.expireOnRefresh(engineID)
            elif oid == usmStatsDecryptionErrorsInstance:
                if requestMessage.header.flags.privFlag:
                    userName = requestMessage.securityName.userName
                    user = self.decodeUserName(userName)
                    handle.report(PrivacyFailure(user))

                    if message.header.flags.authFlag:
                        handle.expire()
                    else:
                        requestState.expireOnRefresh(engineID)
            else:
                handle.report(UnhandledReport(pdu.variableBindings[0]))

                if message.header.flags.authFlag:
                    handle.expire()
                else:
                    requestState.expireOnRefresh(engineID)
        else:
            if pdu.requestID != requestID:
                raise InvalidResponseField(
                    "requestID",
                    pdu.requestID,
                    requestID,
                )
            elif message.header.flags.securityLevel < requestMessage.header.flags.securityLevel:
                raise InvalidResponseField(
                    "securityLevel",
                    message.header.flags.securityLevel,
                    requestMessage.header.flags.securityLevel,
                )
            elif message.scopedPDU.contextEngineID != engineID:
                raise InvalidResponseField(
                    "contextEngineID",
                    message.scopedPDU.contextEngineID,
                    engineID,
                )
            elif message.scopedPDU.contextName != requestMessage.scopedPDU.contextName:
                raise InvalidResponseField(
                    "contextName",
                    message.scopedPDU.contextName,
                    requestMessage.scopedPDU.contextName,
                )
            elif message.securityEngineID != engineID:
                raise InvalidResponseField(
                    "securityEngineID",
                    message.securityEngineID,
                    engineID,
                )
            elif message.securityName.userName != requestMessage.securityName.userName:
                raise InvalidResponseField(
                    "securityName",
                    message.securityName.userName,
                    requestMessage.securityName.userName,
                )
            elif (requestMessage.header.flags.authFlag
            and self.namespace not in message.securityName.namespaces):
                raise NamespaceMismatch(
                    message.securityName.namespaces,
                    self.namespace,
                )

            self.setEngineID(
                message.securityEngineID,
                message.header.flags.authFlag,
            )

            handle.push(pdu)

    def makeRequest(self,
        pdu,
        userName=None,
        securityLevel=None,
        context=b"",
        wait=None,
        timeout=10.0,
        refreshPeriod=1.0,
    ):
        if wait is None:
            wait = self.autowait

        if securityLevel is None:
            securityLevel = self.defaultSecurityLevel

        if userName is None:
            userName = self.defaultUserName

        handle = self.openRequest(timeout)

        if handle.active():
            pdu = pdu.withRequestID(handle.requestID)

            message = SNMPv3Message(
                HeaderData(
                    0,
                    1472,
                    MessageFlags(securityLevel, True),
                    SecurityModel.USM,
                ),
                ScopedPDU(pdu, b"", context),
                b"",
                SecurityName(userName, self.namespace),
            )

            requestState = self.RequestState(handle, message, refreshPeriod)
            self.requests[handle.requestID] = requestState

            if self.engineID is None:
                if self.discovery is None:
                    discoveryHandle = self.openRequestNoTimeout()
                    self.discovery = DiscoveryHandler(
                        discoveryHandle,
                        self.discoveryCallback,
                        self.scheduler,
                        self.thingy,
                        self.sender,
                        self.channel,
                    )

                self.discovery.saveRequest(handle.requestID, refreshPeriod)
            else:
                requestState.send(self.engineID, self)

            handle.addCallback(self.onRequestClosed)

        if wait:
            return handle.wait()
        else:
            return handle

    def get(self, *oids, **kwargs):
        pdu = GetRequestPDU(*oids)
        return self.makeRequest(pdu, **kwargs)

    def getBulk(self, *oids, nonRepeaters=0, maxRepetitions=0, **kwargs):
        pdu = GetBulkRequestPDU(*oids)
        return self.makeRequest(pdu, **kwargs)

    def getNext(self, *oids, **kwargs):
        pdu = GetNextRequestPDU(*oids)
        return self.makeRequest(pdu, **kwargs)

    def set(self, *varbinds, **kwargs):
        pdu = SetRequestPDU(*(VarBind(*vb) for vb in varbinds))
        return self.makeRequest(pdu, **kwargs)
