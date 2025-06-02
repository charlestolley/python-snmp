__all__ = ["SNMPv3Manager"]

import collections
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

class UnhandledReport(IncomingMessageError):
    pass

class SNMPv3Manager:
    def __init__(self,
        director,
        usm,
        channel,
        namespace,
        defaultUserName,
        defaultSecurityLevel,
        autowait,
        engineID = None,
    ):
        self.director = director
        self.usm = usm
        self.channel = channel
        self.namespace = namespace
        self.defaultUserName = defaultUserName.encode()
        self.defaultSecurityLevel = defaultSecurityLevel
        self.autowait = autowait
        self.engineID = engineID

        self.args = {}

        self.auth = False
        self.synchronized = False
        self.discoveryHandle = None
        self.synchronizationHandle = None
        self.unsent = collections.deque()

    def initiateDiscovery(self, timeout):
        self.discoveryHandle = self.director.openRequest(self, timeout)
        self.director.sendRequest(
            self.discoveryHandle.requestID,
            self.channel,
            b"",
            GetRequestPDU(),
            b"",
            noAuthNoPriv,
            b"",
            self.namespace,
            timeout,
        )

        self.discoveryHandle.addCallback(self.onRequestClosed)

    def sendNext(self):
        requestID = self.unsent.popleft()

        try:
            args = self.args[requestID]
        except KeyError:
            return None

        return self.director.sendRequest(
            requestID,
            self.channel,
            self.engineID,
            *args,
        )

    def onRequestClosed(self, requestID):
        if (self.discoveryHandle is not None
        and requestID == self.discoveryHandle.requestID):
            self.discoveryHandle = None

            if self.engineID is None and self.unsent:
                refreshPeriod = self.args[self.unsent[0]][5]
                self.initiateDiscovery(refreshPeriod)

        elif requestID in self.args:
            if (self.synchronizationHandle is not None
            and requestID == self.synchronizationHandle.requestID):
                self.synchronizationHandle = None

                if not self.synchronized and self.unsent:
                    self.synchronizationHandle = self.sendNext()

            try:
                self.unsent.remove(requestID)
            except ValueError:
                pass

            self.args.pop(requestID)

    def processReport(self, report, engineID, auth):
        sendAll = False
        exception = None

        if self.engineID is None:
            self.engineID = engineID

            if (self.discoveryHandle is not None
            and report.requestID == self.discoveryHandle.requestID):
                sendAll = True
                self.director.resetRequest(report.requestID)
                self.discoveryHandle = None

        if not self.synchronized:
            self.synchronized = True

            if (self.synchronizationHandle is not None
            and report.requestID == self.synchronizationHandle.requestID):
                sendAll = True
                self.director.resetRequest(report.requestID)
                self.synchronizationHandle = None

        try:
            vb = report.variableBindings[0]
        except IndexError:
            oid = OID()
        else:
            oid = vb.name

        if oid == usmStatsUnknownEngineIDsInstance:
            if report.requestID in self.args:
                if auth or not self.auth:
                    self.engineID = engineID
                    self.director.resetRequest(report.requestID)

                self.director.sendRequest(
                    report.requestID,
                    self.channel,
                    engineID,
                    *self.args[report.requestID],
                )
        elif oid == usmStatsNotInTimeWindowsInstance:
            if report.requestID in self.args:
                self.director.sendRequest(
                    report.requestID,
                    self.channel,
                    engineID,
                    *self.args[report.requestID],
                )
        elif oid == usmStatsUnsupportedSecLevelsInstance:
            try:
                args = self.args[report.requestID]
            except KeyError:
                exception = UnsupportedSecurityLevel()
            else:
                securityLevel = args[2]
                exception = UnsupportedSecurityLevel(securityLevel)
        elif oid == usmStatsUnknownUserNamesInstance:
            try:
                args = self.args[report.requestID]
            except KeyError:
                exception = UnknownUserName()
            else:
                userName = args[3]

                try:
                    user = userName.decode()
                except UnicodeDecodeError:
                    exception = UnknownUserName(userName)
                else:
                    exception = UnknownUserName(user)

        elif oid == usmStatsWrongDigestsInstance:
            try:
                args = self.args[report.requestID]
            except KeyError:
                exception = WrongDigest()
            else:
                userName = args[3]

                try:
                    user = userName.decode()
                except UnicodeDecodeError:
                    exception = WrongDigest(userName)
                else:
                    exception = WrongDigest(user)
        elif oid == usmStatsDecryptionErrorsInstance:
            try:
                args = self.args[report.requestID]
            except KeyError:
                exception = DecryptionError()
            else:
                userName = args[3]

                try:
                    user = userName.decode()
                except UnicodeDecodeError:
                    exception = DecryptionError(userName)
                else:
                    exception = DecryptionError(user)
        else:
            exception = UnhandledReport(report)

        if auth and not self.auth:
            self.auth = True

        if sendAll:
            while self.unsent:
                self.sendNext()

        return exception

    def processResponse(self, response, engineID, auth):
        if auth:
            self.engineID = engineID

            if not self.auth:
                self.auth = True

        if not self.synchronized:
            self.synchronized = True

            if self.synchronizationHandle is not None:
                if response.requestID == self.synchronizationHandle.requestID:
                    self.synchronizationHandle = None
                elif self.synchronizationHandle.requestID in self.args:
                    self.director.sendRequest(
                        self.synchronizationHandle.requestID,
                        self.channel,
                        engineID,
                        *self.args[self.synchronizationHandle.requestID],
                    )

                while self.unsent:
                    self.sendNext()

        return True

    def makeRequest(self,
        pdu: AnyPDU,
        contextName = b"",
        securityLevel = None,
        user = None,
        wait = None,
        timeout = 10.0,
        refreshPeriod = 1.0,
    ):
        if securityLevel is None:
            securityLevel = self.defaultSecurityLevel

        if user is None:
            userName = self.defaultUserName
        else:
            userName = user.encode()

        if wait is None:
            wait = self.autowait

        handle = self.director.openRequest(self, timeout)

        args = (
            pdu,
            contextName,
            securityLevel,
            userName,
            self.namespace,
            refreshPeriod,
        )

        self.args[handle.requestID] = args

        send = True
        if self.engineID is None:
            if self.discoveryHandle is None:
                self.initiateDiscovery(refreshPeriod)

            send = False
        else:
            if securityLevel.auth and not self.synchronized:
                if self.synchronizationHandle is None:
                    self.synchronizationHandle = handle
                else:
                    send = False

        if send:
            self.director.sendRequest(
                handle.requestID,
                self.channel,
                self.engineID,
                *args,
            )
        else:
            self.unsent.append(handle.requestID)

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

# What is a request?
# - a request is the basic unit of communication between two engines
# - every request or notification should have a unique request ID
# What is a message?
# A message is active until it expires
# - it's possible to receive multiple replies to a message (?)
# - every message is part of a request
# - when the request is fulfilled, then the messages should be dropped
# - there should only be one active message per request at any one time
# - for an incoming message, you should look up the request ID
# - a report message might have a 0 requestID, but otherwise it should match
# What is a request handle?
# - a request handle is the way to report the result of a request to the application
# - The user calls "wait()", which can return a VarBindList, raise a Timeout, an
#   ErrorStatus, or some other kind of error, indicating problems with authentication,
#   or a mismatch between the requested OIDs and the contents of the response
# - the handle should not be used to track any other state of the request
#
# A standard request should have a task scheduled to expire the handle after the timeout
# It should have a second task scheduled to periodically expire the message and send a new one
# A discovery request should have a task scheduled to periodically expire the message and send a new one
# - once the last request expires, this task should be cancelled
# The Director and Secretary should probably be merged into one
# The manager opens a request, which allocates a request ID and creates a handle
# - the handle has a callback to release the request ID
# The manager creates a message for the request, and asks for it to be sent
# - the sender allocates a new messageID, and stores a reference to the manager so it can call back to it when a reply comes in

# TODO: Add withMessageID to HeaderData and SNMPv3Message
# TODO: Add withEngineID to ScopedPDU and SNMPv3Message

# Requests: The order only matters for setting discovery message refresh periods, and that's really not all that important
# Perhaps the discovery request should just permanently use the refreshPeriod of the first request. Either way, it doesn't matter, as this is a nearly irrelevant use-case. Most people won't use the refreshPeriod argument, and they are not likely to care what refreshPeriod it uses if everything times out.
# For each request, spawn a message dispatch task, with the right period. Each time a message is sent, it should expire the old message. There should not be a dedicated message expire task; the send task should probably expire the old message, somehow.
# Is the discovery request just like any other request? Maybe, except it does not have a timeout. It expires when the last unsent request expires.

# For a message, the following needs to match:
# - message ID
# For a report
# - match it up using the message ID
# For a response
# - match it up using pdu.requestID
# Reject the response if the following don't match
# - securityModel
# - header.flags.authFlag
# - header.flags.privFlag
# - securityEngineID
# - securityName.userName
# - namespace not in securityName.namespaces
# Raise an exception in handle.wait() if
# - errorStatus is non-zero
# - the layout of the VarBindList does not match the request
#   - you should be able to turn off this behavior
#SNMPv3Message(
#    HeaderData(
#        msgID,
#        maxSize,
#        flags,
#        securityModel,
#    ),
#    ScopedPDU(
#        pdu,
#        contextEngineID,
#        contextName,
#    ),
#    securityEngineID,
#    securityName,
#)

# Make something that handles messages, so it can correlate replies to their messages
# It will have a task to refresh discovery
# But the discovery message should be tied to a request handle for a real request
# and if that request is expired, then the refresh task will need to trigger a new discovery request

class Thingy3:
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

class NotAMessage:
    def __init__(self, pdu, userName, securityLevel):
        self.pdu = pdu
        self.securityLevel = securityLevel
        self.userName = userName

class RequestInfo:
    def __init__(self, handle, message, refreshPeriod):
        self.handle_ref = weakref.ref(handle)
        self.message = message
        self.refreshPeriod = refreshPeriod

class DiscoveryState:
    class RefreshTask(SchedulerTask):
        def __init__(self, handle, messageID, discoveryState):
            self.handle_ref = weakref.ref(handle)
            self.discoveryState = discoveryState
            self.messageID = messageID

        def run(self):
            self.discoveryState.manager.thingy.releaseMessageID(self.messageID)

            handle = self.handle_ref()
            if handle is not None and handle.active():
                self.discoveryState.sendDiscoveryMessage()

    def __init__(self, manager):
        self.handle = None
        self.manager = manager
        self.unsent = collections.deque()

    def hear(self, message):
        self.handle.expire()
        self.handle = None

        self.manager.engineID = message.securityEngineID
        self.manager.internalState = SteadyState(self.manager)

        for requestInfo in self.unsent:
            handle = requestInfo.handle_ref()

            if handle is None:
                continue

            self.manager.internalState.makeRequest(
                handle,
                requestInfo.message.pdu,
                requestInfo.message.userName,
                requestInfo.message.securityLevel,
                requestInfo.refreshPeriod,
            )

    def sendDiscoveryMessage(self):
        if self.handle is None or not self.unsent:
            return

        refreshPeriod = self.unsent[0].refreshPeriod
        messageID = self.manager.thingy.reserveMessageID(self)
        message = SNMPv3Message(
            HeaderData(
                messageID,
                1472,
                MessageFlags(reportable=True),
                SecurityModel.USM,
            ),
            ScopedPDU(
                GetRequestPDU(requestID=self.handle.requestID),
                b"",
            ),
            b"",
            SecurityName(b""),
        )

        self.manager.sender.send(message, self.manager.channel)
        task = self.RefreshTask(self.handle, messageID, self)
        self.manager.scheduler.schedule(task, refreshPeriod)

    def makeRequest(self, handle, pdu, userName, securityLevel, refreshPeriod):
        message = NotAMessage(pdu, userName, securityLevel)
        requestInfo = RequestInfo(handle, message, refreshPeriod)
        self.unsent.append(requestInfo)

        if self.handle is None:
            self.handle = self.manager.openRequestNoTimeout()
            self.sendDiscoveryMessage()

    def onRequestClosed(self, requestID):
        while self.unsent:
            handle = self.unsent[0].handle_ref()
            if handle is not None and handle.active():
                break

            self.unsent.popleft()
        else:
            if (self.handle is not None
            and self.handle.active()):
                self.handle.expire()
                self.handle = None

class SteadyState:
    def __init__(self, manager):
        self.manager = manager

    def makeRequest(self, handle, pdu, userName, securityLevel, refreshPeriod):
        if not handle.active():
            return

        message = SNMPv3Message(
            HeaderData(
                0,
                1472,
                MessageFlags(securityLevel, True),
                SecurityModel.USM,
            ),
            ScopedPDU(pdu.withRequestID(handle.requestID), self.manager.engineID),
            self.manager.engineID,
            SecurityName(userName, self.manager.namespace),
        )

        self.manager.messages[handle.requestID] = message
        self.manager.requests[handle.requestID] = handle
        sendTask = self.manager.SendTask(handle, self.manager)
        self.manager.scheduler.schedule(sendTask, period=refreshPeriod)

    def onRequestClosed(self, requestID):
        del self.manager.requests[requestID]
        message = self.manager.messages.pop(requestID)
        self.manager.thingy.releaseMessageID(message.header.msgID)

class SNMPv3Manager3:
    class DiscoveryTask(SchedulerTask):
        def __init__(self, handle, messageID, manager):
            self.handle_ref = weakref.ref(handle)
            self.manager = manager
            self.messageID = messageID

        def run(self):
            self.manager.thingy.releaseMessageID(self.messageID)

            handle = self.handle_ref()
            if handle is not None and handle.active():
                self.manager.sendDiscoveryMessage()

    class ExpireTask(SchedulerTask):
        def __init__(self, handle):
            self.handle_ref = weakref.ref(handle)

        def run(self):
            handle = self.handle_ref()

            if handle is not None:
                handle.expire()

    class SendTask(SchedulerTask):
        def __init__(self, handle, manager):
            self.handle_ref = weakref.ref(handle)
            self.manager = manager

        def run(self):
            handle = self.handle_ref()

            if handle is not None and handle.active():
                self.manager.sendRequest(handle.requestID)
                return self
            else:
                return None

    def __init__(self,
        scheduler,
        thingy,
        sender,
        channel,
        namespace,
        defaultUserName,
        defaultSecurityLevel,
        engineID,
    ):
        self.channel = channel
        self.scheduler = scheduler
        self.sender = sender
        self.thingy = thingy

        self.engineID = engineID
        self.namespace = namespace
        self.defaultUserName = defaultUserName
        self.defaultSecurityLevel = defaultSecurityLevel

        self.requestIDAuthority = RequestIDAuthority()

        self.requests = {}
        self.messages = {}

        if self.engineID is None:
            self.internalState = DiscoveryState(self)
        else:
            self.internalState = SteadyState(self)

    def hear(self, message):
        pdu = message.scopedPDU.pdu

        try:
            handle = self.requests[pdu.requestID]
        except KeyError:
            raise IncomingMessageError(f"Unknown requestID: {pdu.requestID}")

        if pdu.INTERNAL_CLASS:
            pass
        else:
            # TODO: Verify the response
            handle.push(pdu)

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
        self.internalState.onRequestClosed(requestID)

    def sendRequest(self, requestID):
        message = self.messages[requestID]
        messageID = message.header.msgID

        if messageID != 0:
            self.thingy.releaseMessageID(messageID)

        if self.engineID is None:
            engineID = b""
        else:
            engineID = self.engineID

        messageID = self.thingy.reserveMessageID(self)
        message = SNMPv3Message(
            HeaderData(
                messageID,
                message.header.maxSize,
                message.header.flags,
                message.header.securityModel,
            ),
            ScopedPDU(
                message.scopedPDU.pdu,
                engineID,
                message.scopedPDU.contextName,
            ),
            message.securityEngineID,
            message.securityName,
        )

        self.messages[requestID] = message
        self.sender.send(message, self.channel)

    def makeRequest(self, pdu, userName=None, securityLevel=None, timeout=10.0, refreshPeriod=1.0):
        if securityLevel is None:
            securityLevel = self.defaultSecurityLevel

        if userName is None:
            userName = self.defaultUserName

        handle = self.openRequest(timeout, self.onRequestClosed)
        self.internalState.makeRequest(handle, pdu, userName, securityLevel, refreshPeriod)
        return handle

# Manager needs:
# - hear
# - onRequestClosed
#   - call releaseMessageID
# - sendRequest
#   - call reserveMessageID
# - RefreshTask(handle, manager)
#   - call sendRequest (if handle is active)
#   - return self
# Thingy needs:
# - reserveMessageID(manager)
# - releaseMessageID(messageID)

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

# Problems:
# The thingy needs to know what messages are outstanding
# When a message expires, its messageID needs to be deallocated
# Options:
# The manager creates a recurring task to send the message
# - every period, it calls sendMessage, which allocates a requestID, and sends the message over the channel
# A message should be closed when the request that owns it is closed
# A message should be closed as the next message of the same request is opened
# The manager holds the channel, so maybe the manager should send it
# The thingy is the point where all replies are received
# openMessage(message)
# - return a copy with the newly reserved message ID
# renewMessage(message)
# - release the old message ID and reserve a new one
# - return a copy with the new message ID
# closeMessage(message)
# - release the message ID
# The task would
# - Call the manger to service the request with the given requestID
# - all it needs is the handle (weakref) and the manager
# The manager would have a method like, "sendRequest(requestID)"
# - perhaps the open and renew message methods are the same, but with a special case for
#   when the message ID is zero
# Add a callback to the request handle to close the message for its request ID
# - this callback would be to the manager
# Manager needs a dict of requestID -> message
# Thingy needs a dict of messageID -> manager
# RefreshTask needs a requestHandle (weak reference) and a manger (strong reference)
# Manager has a thingy reference
# Thingy has a weak manager reference (WeakValueDictionary)
# The request handle keeps the manager alive, the manager keeps the thingy alive,
# but if the request handle and the manager are dropped, the thingy drops the manager
# - if that happens, how does the message ID get released?
# - the request handle has a callback to the manager, which closes the active message
