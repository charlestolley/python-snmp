__all__ = [
    "RequestError",
    "AuthenticationFailure", "PrivacyFailure", "TimeWindowFailure",
    "UnknownUserName", "UnsupportedSecurityLevel", "UnhandledReport",
    "InvalidResponseField", "NamespaceMismatch",
    "SNMPv3Manager", "SNMPv3MessageTable",
]

import collections
import re
import weakref

from snmp.exception import *
from snmp.pdu import *
from snmp.scheduler import *
from snmp.security import *
from snmp.security.usm.stats import *
from snmp.requests import *
from snmp.v3.message import *
from snmp.v3.requests import *

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

class SNMPv3MessageTable:
    def __init__(self):
        self.authority = MessageIDAuthority()
        self.listeners = {}

    def hear(self, message, channel):
        messageID = message.header.msgID

        try:
            listener = self.listeners[messageID]
        except KeyError:
            raise IncomingMessageError(f"Unknown message ID: {messageID}")

        listener.hear(message)

    def reserveMessageID(self, listener):
        messageID = self.authority.reserve()
        self.listeners[messageID] = listener
        return messageID

    def releaseMessageID(self, messageID):
        try:
            del self.listeners[messageID]
        except KeyError:
            pass

        self.authority.release(messageID)

class DiscoveryHandler:
    class RefreshTask(SchedulerTask):
        def __init__(self, handler):
            self.handler = handler

        def cancel(self):
            self.handler = None

        def run(self):
            if self.handler is not None:
                self.handler.expireMessage()
                self.handler.sendNewMessage()
                self.handler.scheduleRefresh()

    def __init__(self, handle, callback, scheduler, table, sender, channel):
        self.channel = channel
        self.sender = sender
        self.scheduler = scheduler
        self.table = table

        self.messageID = 0
        self.refreshTask = None
        self.unsent = collections.OrderedDict()

        self.callback = callback
        self.handle = handle

    def hear(self, message):
        self.stopDiscovery()
        self.callback(message.securityEngineID)

    def expireMessage(self):
        self.table.releaseMessageID(self.messageID)

    def sendNewMessage(self):
        self.messageID = self.table.reserveMessageID(self)

        message = SNMPv3Message(
            HeaderData(
                self.messageID,
                self.channel.msgMaxSize,
                MessageFlags(reportable=True),
                SecurityModel.USM,
            ),
            ScopedPDU(self.handle.pdu, b""),
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

class ExpireTask(SchedulerTask):
    def __init__(self, handle):
        self.handle_ref = weakref.ref(handle)

    def run(self):
        handle = self.handle_ref()

        if handle is not None:
            handle.expire()

class SendTask(SchedulerTask):
    def __init__(self, handle, message, engineID, manager):
        self.cancelled = False
        self.exception = False

        self.message = message
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

        self.messageID = self.manager.allocateMessage(
            handle.requestID,
            self.engineID,
        )

        message = self.message \
            .withMessageID(self.messageID) \
            .withEngineID(self.engineID)

        self.manager.sender.send(message, self.manager.channel)
        return self

class RequestState:
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

        sendTask = SendTask(self.handle, self.message, engineID, manager)
        manager.scheduler.schedule(sendTask, period=self.refreshPeriod)
        self.tasks[engineID] = sendTask

class SNMPv3Manager:
    def __init__(self,
        scheduler,
        table,
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
        self.table = table

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

    def openRequestNoTimeout(self, pdu, *callbacks):
        requestID = self.requestIDAuthority.reserve()
        handle = SNMPv3RequestHandle(
            self.scheduler,
            pdu.withRequestID(requestID),
            # Callbacks
            self.requestIDAuthority.release,
            *callbacks,
        )

        return handle

    def openRequest(self, pdu, timeout, *callbacks):
        handle = self.openRequestNoTimeout(pdu, *callbacks)
        self.scheduler.schedule(ExpireTask(handle), timeout)
        return handle

    def onRequestClosed(self, requestID):
        if self.engineID is None:
            if (self.discovery is not None
            and self.discovery.dropRequest(requestID)):
                self.discovery = None

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
        messageID = self.table.reserveMessageID(self)
        self.mapping[messageID] = requestID, engineID
        return messageID

    def deallocateMessage(self, messageID):
        del self.mapping[messageID]
        self.table.releaseMessageID(messageID)

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
        contextName = message.scopedPDU.contextName
        securityLevel = message.header.flags.securityLevel
        securityName = message.securityName

        if pdu.INTERNAL_CLASS:
            if len(pdu.variableBindings) < 1:
                raise IncomingMessageError("No OIDs in report")

            oid = pdu.variableBindings[0].name
            if oid == usmStatsUnknownEngineIDsInstance:
                requestState.send(message.securityEngineID, self)
            elif message.securityEngineID != engineID:
                errmsg = "Engine ID does not match the request"
                raise IncomingMessageError(errmsg)
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

                if securityLevel < requestSecLevel:
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
            elif securityLevel < requestMessage.header.flags.securityLevel:
                raise InvalidResponseField(
                    "securityLevel",
                    securityLevel,
                    requestMessage.header.flags.securityLevel,
                )
            elif message.scopedPDU.contextEngineID != engineID:
                raise InvalidResponseField(
                    "contextEngineID",
                    message.scopedPDU.contextEngineID,
                    engineID,
                )
            elif contextName != requestMessage.scopedPDU.contextName:
                raise InvalidResponseField(
                    "contextName",
                    contextName,
                    requestMessage.scopedPDU.contextName,
                )
            elif message.securityEngineID != engineID:
                raise InvalidResponseField(
                    "securityEngineID",
                    message.securityEngineID,
                    engineID,
                )
            elif securityName.userName != requestMessage.securityName.userName:
                raise InvalidResponseField(
                    "securityName",
                    securityName.userName,
                    requestMessage.securityName.userName,
                )
            elif (requestMessage.header.flags.authFlag
            and self.namespace not in securityName.namespaces):
                raise NamespaceMismatch(
                    securityName.namespaces,
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

        handle = self.openRequest(pdu, timeout)

        if handle.active():
            header = HeaderData(
                0,
                self.channel.msgMaxSize,
                MessageFlags(securityLevel, True),
                SecurityModel.USM,
            )

            scopedPDU = ScopedPDU(handle.pdu, b"", context)
            securityName = SecurityName(userName, self.namespace)
            message = SNMPv3Message(header, scopedPDU, b"", securityName)

            requestState = RequestState(handle, message, refreshPeriod)
            self.requests[handle.requestID] = requestState

            if self.engineID is None:
                if self.discovery is None:
                    self.discovery = DiscoveryHandler(
                        self.openRequestNoTimeout(GetRequestPDU()),
                        self.discoveryCallback,
                        self.scheduler,
                        self.table,
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
        pdu = GetBulkRequestPDU(
            *oids,
            nonRepeaters=nonRepeaters,
            maxRepetitions=maxRepetitions,
        )

        return self.makeRequest(pdu, **kwargs)

    def getNext(self, *oids, **kwargs):
        pdu = GetNextRequestPDU(*oids)
        return self.makeRequest(pdu, **kwargs)

    def set(self, *varbinds, **kwargs):
        pdu = SetRequestPDU(*varbinds)
        return self.makeRequest(pdu, **kwargs)
