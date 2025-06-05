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
from snmp.utils import typename

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

# DiscoveryHandler just needs handles and refreshPeriods
# RequestsHandler should have a save function, and then a way to send all
# When an Unknown Engine ID report comes in, it needs to call back to the
# manager to set the engineID, and then a way to cancel and re-send all
# requests with the new requestID.
# However, for now, it's easier if we just assume that an engineID can
# never change after it's been initially configured.
# In that case, we need to keep track of the messageID that carries each
# request, and when a message comes in, we find the request handle using
# the messageID, but then confirm that the requestID matches as well

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

                message = self.manager.requests[handle.requestID].message

                message = SNMPv3Message(
                    message.header.withMessageID(self.messageID),
                    ScopedPDU(
                        message.scopedPDU.pdu,
                        self.engineID,
                        message.scopedPDU.contextName,
                    ),
                    self.engineID,
                    message.securityName,
                )

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
    ):
        self.channel = channel
        self.sender = sender
        self.thingy = thingy

        self.engineIDAuthenticated = False
        self.engineID = engineID
        self.namespace = namespace

        self.defaultUserName = defaultUserName
        self.defaultSecurityLevel = defaultSecurityLevel

        self.scheduler = scheduler
        self.requestIDAuthority = RequestIDAuthority()

        self.discovery = None

        self.mapping = {}
        self.requests = {}

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

    # TODO: Send all requests in setEngineID and get rid of this method
    def discoveryCallback(self, engineID):
        self.discovery = None
        self.setEngineID(engineID, False)

# Each SendTask has one messageID at a time
# The manager should have a cancel message function, which releases the messageID
# The sendMessage should return the messageID, so the SendTask can store it
# But we also need a way to find the SendTask for a messageID

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
            raise IncomingMessageError(errmsg) from err

        requestState = self.requests[requestID]
        handle = requestState.handle
        requestMessage = requestState.message

        pdu = message.scopedPDU.pdu
        if pdu.INTERNAL_CLASS:
            if len(pdu.variableBindings) < 1:
                raise IncomingMessageError("No OIDs in report")

            oid = pdu.variableBindings[0].name
            if oid == usmStatsUnknownEngineIDsInstance:
                requestState.send(message.securityEngineID, self)
            elif message.securityEngineID != engineID:
                raise IncomingMessageError("Engine ID does not match the request")
            elif oid == usmStatsNotInTimeWindowsInstance:
                # TODO: Check authFlag of the incoming message
                if requestMessage.header.flags.authFlag:
                    refreshPeriod = requestState.refreshPeriod
                    cancelled = requestState.cancel(engineID)

                    if cancelled:
                        requestState.resend(engineID, self)
                    else:
                        handle.report(OutsideTimeWindow())
                        if message.header.flags.authFlag:
                            handle.expire()
                        else:
                            requestState.expireOnRefresh(engineID)
            elif oid == usmStatsUnsupportedSecLevelsInstance:
                requestSecLevel = requestMessage.header.flags.securityLevel
                reportSecLevel = message.header.flags.securityLevel

                if reportSecLevel < requestSecLevel:
                    handle.report(UnsupportedSecLevel(requestSecLevel))

                    if message.header.flags.authFlag:
                        handle.expire()
                    else:
                        requestState.expireOnRefresh(engineID)
            elif oid == usmStatsUnknownUserNamesInstance:
                if not message.header.flags.authFlag:
                    userName = requestMessage.securityName.userName

                    try:
                        user = userName.decode()
                    except UnicodeDecodeError:
                        user = None

                    handle.report(UnknownUserName(user))
                    requestState.expireOnRefresh(engineID)
            elif oid == usmStatsWrongDigestsInstance:
                if requestMessage.header.flags.authFlag:
                    userName = requestMessage.securityName.userName

                    try:
                        user = userName.decode()
                    except UnicodeDecodeError:
                        user = None

                    handle.report(WrongDigest(user))
                    requestState.expireOnRefresh(engineID)
            elif oid == usmStatsDecryptionErrorsInstance:
                if requestMessage.header.flags.privFlag:
                    userName = requestMessage.securityName.userName

                    try:
                        user = userName.decode()
                    except UnicodeDecodeError:
                        user = None

                    handle.report(DecryptionError(user))

                    if message.header.flags.authFlag:
                        handle.expire()
                    else:
                        requestState.expireOnRefresh(engineID)
        else:
            if pdu.requestID != requestID:
                raise IncomingMessageError("Unhelpful message")

            self.setEngineID(
                message.securityEngineID,
                message.header.flags.authFlag,
            )

            handle.push(pdu)

    def makeRequest(self, pdu, userName=None, securityLevel=None, timeout=10.0, refreshPeriod=1.0):
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
                ScopedPDU(pdu, b""),
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
