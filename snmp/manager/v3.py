__all__ = ["SNMPv3UsmManager"]

from collections import deque
import heapq
import math
import threading
import time
import weakref

from snmp.exception import *
from snmp.message import *
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import *
from snmp.types import *
from snmp.utils import *
from . import *

usmStats = OID.parse("1.3.6.1.6.3.15.1.1")
usmStatsUnsupportedSecLevelsSubTree     = (1, 0)
usmStatsNotInTimeWindowsInstanceSubTree = (2, 0)
usmStatsUnknownUserNamesSubTree         = (3, 0)
usmStatsUnknownEngineIDsInstanceSubTree = (4, 0)
usmStatsWrongDigestsSubTree             = (5, 0)
usmStatsDecryptionErrorsSubTree         = (6, 0)

class UnhandledReport(SNMPException):
    pass

class UnrecognizedReport(UnhandledReport):
    def __init__(self, varbind):
        super().__init__(f"Remote Engine sent this Report: \"{varbind}\"")
        self.name = varbind.name
        self.value = varbind.value

class UsmStatsReport(UnhandledReport):
    def __init__(self, errmsg, varbind):
        super().__init__(errmsg)
        self.name = varbind.name
        self.value = varbind.value

class UnsupportedSecurityLevelReport(UsmStatsReport):
    def __init__(self, message, varbind):
        errmsg = f"Remote Engine does not support {message.securityLevel}"
        super().__init__(errmsg, varbind)

class UnknownUserNameReport(UsmStatsReport):
    def __init__(self, message, varbind):
        userName = message.securityName.decode()
        errmsg = f"Remote Engine does not recognize user \"{userName}\""
        super().__init__(errmsg, varbind)

class WrongDigestReport(UsmStatsReport):
    def __init__(self, message, varbind):
        userName = message.securityName.decode()

        errmsg = (
            "Remote Engine reported that your request failed authentication"
            f"; make sure \"{userName}\" is using the correct credentials"
        )

        super().__init__(errmsg, varbind)

class DecryptionErrorReport(UsmStatsReport):
    def __init__(self, message, varbind):
        errmsg = "Remote Engine was unable to decrypt your request"
        super().__init__(errmsg, varbind)

class DiscoveryError(IncomingMessageError):
    pass

class State:
    def __init__(self, arg):
        if isinstance(arg, State):
            self.manager = arg.manager
        else:
            self.manager = weakref.proxy(arg)

# User did not provide an engine ID, and
# has not yet attempted to send any requests
class Inactive(State):
    def onInactive(self):
        pass

    def onRequest(self, auth):
        self.manager.state = WaitForDiscovery(self)
        return True

    def onReport(self, engineID):
        errmsg = "Received a report where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

    def onResponse(self, engineID, auth):
        errmsg = "Received a response where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

# User provided an engine ID, but has not yet sent any requests
class Unsynchronized(State):
    def onInactive(self):
        pass

    def onRequest(self, auth):
        self.manager.state = Synchronizing(self)
        return True

    def onReport(self, engineID):
        errmsg = "Received a report where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

    def onResponse(self, engineID, auth):
        errmsg = "Received a response where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

# User did not provide an engine ID, and the Manager has not
# yet received any communication from the remote engine.
class WaitForDiscovery(State):
    def onInactive(self):
        self.manager.state = Inactive(self)

    def onRequest(self, auth):
        return False

    def onReport(self, engineID):
        self.manager.state = TrustEveryResponse(self)
        return True

    def onResponse(self, engineID, auth):
        errmsg = "Received a ResponsePDU in response to a discovery message"
        raise DiscoveryError(errmsg)

# User provided engineID and has sent at least one request, but the
# Manager has not yet received any communication from the remote engine.
class Synchronizing(State):
    def onInactive(self):
        self.manager.state = Unsynchronized(self)

    def onRequest(self, auth):
        return not auth

    def onReport(self, engineID):
        if self.manager.engineID == engineID:
            self.manager.state = RequireAuthentication(self)
            return True
        else:
            return False

    def onResponse(self, engineID, auth):
        if auth or self.manager.engineID == engineID:
            self.manager.state = RequireAuthentication(self)
            return True
        else:
            return False

class TrustEveryResponse(State):
    def onInactive(self):
        pass

    def onRequest(self, auth):
        return True

    def onReport(self, engineID):
        return False

    def onResponse(self, engineID, auth):
        if auth:
            self.manager.state = RequireAuthentication(self)

        return True

class RequireAuthentication(State):
    def onInactive(self):
        pass

    def onRequest(self, auth):
        return True

    def onReport(self, engineID):
        return False

    def onResponse(self, engineID, auth):
        return auth

class RequestMessage(RequestHandle):
    USM_EXCEPTION_TYPES = {
        usmStatsUnsupportedSecLevelsSubTree:    UnsupportedSecurityLevelReport,
        usmStatsUnknownUserNamesSubTree:        UnknownUserNameReport,
        usmStatsWrongDigestsSubTree:            WrongDigestReport,
        usmStatsDecryptionErrorsSubTree:        DecryptionErrorReport,
    }

    def __init__(self, request, synchronized):
        self.request = weakref.proxy(request)
        self.messageID = None
        self.callback = None

        self.synchronized = synchronized

    def addCallback(self, func, msgID):
        self.callback = func
        self.messageID = msgID

    def push(self, response):
        pdu = response.data.pdu

        if isinstance(pdu, ReportPDU):
            securityLevel = response.securityLevel
            varbind = response.data.pdu.variableBindings[0]

            oid = varbind.name
            subtree = oid.getSubTree(usmStats)
            if subtree == usmStatsUnknownEngineIDsInstanceSubTree:
                self.request.processUnknownEngineID(response.securityEngineID)
            elif subtree == usmStatsNotInTimeWindowsInstanceSubTree:
                if not self.synchronized:
                    engineID = response.securityEngineID
                    self.request.processNotInTimeWindow(engineID)
            else:
                try:
                    exc_type = self.USM_EXCEPTION_TYPES[subtree]
                except KeyError:
                    exception = UnrecognizedReport(varbind)
                else:
                    exception = exc_type(response, varbind)

                auth = response.securityLevel.auth
                self.request.processException(exception, auth)
        else:
            self.request.processResponse(response)

    def close(self):
        if self.callback is not None:
            self.callback(self.messageID)
            self.callback = None

class SharedBool:
    def __init__(self, value):
        self.value = value

    def __bool__(self):
        return self.value

    def makeTrue(self):
        self.value = True

    def makeFalse(self):
        self.value = False

class Request:
    def __init__(self, pdu, manager, userName, securityLevel,
                            timeout=10.0, refreshPeriod=1.0):
        now = time.time()

        self._engineID = None
        self.synchronized = SharedBool(False)

        self.manager = manager
        self.pdu = pdu
        self.securityLevel = securityLevel
        self.userName = userName

        self.messages = set()

        self.event = threading.Event()
        self.exception = None
        self.response = None

        self.expiration = now + timeout
        self.nextRefresh = float("inf")
        self.period = refreshPeriod

    def __del__(self):
        self.close()

    def __lt__(self, other):
        a = min(self .expiration, self .nextRefresh)
        b = min(other.expiration, other.nextRefresh)
        return a < b

    @property
    def engineID(self):
        return self._engineID

    @engineID.setter
    def engineID(self, engineID):
        if engineID == self._engineID:
            return

        if engineID is not None:
            self.manager.registerRemoteEngine(engineID)

        if self._engineID is not None:
            self.manager.unregisterRemoteEngine(self._engineID)

        self._engineID = engineID

    @property
    def expired(self):
        return self.expiration <= time.time()

    def close(self):
        while self.messages:
            self.messages.pop().close()

        self.engineID = None

    def processNotInTimeWindow(self, engineID):
        self.manager.onReport(self, engineID)
        self.synchronized.makeTrue()
        self.synchronized = SharedBool(False)

    def processUnknownEngineID(self, engineID):
        if engineID != self.engineID:
            self.manager.onReport(self, engineID)

    def processException(self, exception, auth):
        if auth:
            if not self.event.is_set():
                self.exception = exception
                self.event.set()
        elif self.exception is None:
            self.exception = exception

    def processResponse(self, response):
        #if random.randint(1, 3) % 3 != 0:
        #    return

        if self.manager.processResponse(self, response):
            if not self.event.is_set():
                self.response = response
                self.event.set()

    def reallySend(self, engineID=None):
        pdu = self.pdu
        user = self.userName
        securityLevel = self.securityLevel

        if engineID is None:
            if self.engineID is None:
                pdu = GetRequestPDU()
                engineID = b""
                user = b""
                securityLevel = noAuthNoPriv
            else:
                engineID = self.engineID
        else:
            self.engineID = engineID

        message = RequestMessage(self, self.synchronized)
        self.messages.add(message)
        self.manager.sendPdu(pdu, message, engineID, user, securityLevel)

    def refresh(self):
        if self.event.is_set():
            return None

        now = time.time()
        expireTime = self.expiration - now
        if expireTime <= 0.0:
            return None

        refreshTime = self.nextRefresh - now
        delta = min(expireTime, refreshTime)

        if delta < 0.0:
            self.nextRefresh += math.ceil(-delta / self.period) * self.period
            self.reallySend()
            return 0.0
        else:
            return delta

    def send(self, engineID=None):
        now = time.time()
        self.nextRefresh = now + self.period
        self.reallySend(engineID)

    def wait(self):
        try:
            pdu = None
            while not self.expired:
                timeout = self.manager.refresh()

                try:
                    ready = self.event.wait(timeout=timeout)
                except KeyboardInterrupt as interrupt:
                    if self.exception is not None:
                        raise self.exception from interrupt
                    else:
                        raise

                if ready:
                    break

            if self.event.is_set() and self.response is not None:
                return self.response.data.pdu
            else:
                if self.exception is not None:
                    raise self.exception
                else:
                    raise Timeout()
        finally:
            self.close()

class SNMPv3UsmManager:
    def __init__(self, dispatcher, usm, locator, namespace,
            defaultUserName, defaultSecurityLevel,
            engineID=None, autowait=True):

        # Used by @property
        self._engineID = None

        # Read-only fields
        self.locator = locator
        self.namespace = namespace
        self.defaultUserName = defaultUserName
        self.defaultSecurityLevel = defaultSecurityLevel
        self.autowait = autowait

        self.dispatcher = dispatcher
        self.usm = usm

        self.generator = self.newGenerator()

        # protects self.active
        self.activeLock = threading.Lock()
        self.active = []

        # protects self.unsent, self.state, and self.engineID
        self.lock = threading.Lock()
        self.unsent = deque()

        if engineID is None:
            self.state = Inactive(self)
        else:
            self.engineID = engineID
            self.state = Unsynchronized(self)

    def __del__(self):
        self.engineID = None

    @property
    def engineID(self):
        return self._engineID

    @engineID.setter
    def engineID(self, engineID):
        if engineID == self._engineID:
            return

        if engineID is not None:
            self.registerRemoteEngine(engineID)

        if self._engineID != None:
            self.unregisterRemoteEngine(self._engineID)

        self._engineID = engineID

    def generateRequestID(self):
        requestID = next(self.generator)

        if requestID == 0:
            self.generator = self.newGenerator()
            requestID = next(self.generator)

        return requestID

    def newGenerator(self):
        return NumberGenerator(32)

    def drop(self, reference):
        with self.activeLock:
            for i, item in enumerate(self.active):
                if item is reference:
                    self.active.pop(i)
                    heapq.heapify(self.active)
                    break

    def poke(self):
        active = False
        with self.lock:
            self.state.onInactive()

            unsent = self.unsent
            self.unsent = deque()
            while unsent:
                reference = unsent.pop()
                request = reference()

                if request is not None:
                    if self.state.onRequest(request.securityLevel.auth):
                        with self.activeLock:
                            request.send(self.engineID)
                            heapq.heappush(self.active, reference)
                            active = True
                    else:
                        self.unsent.appendleft(reference)

        return active

    def refresh(self):
        active = True
        while active:
            with self.activeLock:
                if self.active:
                    reference = self.active[0]
                    request = reference()

                    if request is None:
                        wait = None
                    else:
                        wait = request.refresh()

                    if wait is None:
                        heapq.heappop(self.active)
                        continue
                    elif wait > 0.0:
                        return wait
                    else:
                        heapq.heapreplace(self.active, reference)

                    active = True
                else:
                    active = False

            if not active:
                active = self.poke()

        return 0.0

    def registerRemoteEngine(self, engineID):
        if not self.usm.registerRemoteEngine(engineID, self.namespace):
            errmsg = f"Failed to register engineID {engineID}"

            if self.namespace:
                errmsg += f" under namespace \"{self.namespace}\""

            raise DiscoveryError(errmsg)

    def unregisterRemoteEngine(self, engineID):
        self.usm.unregisterRemoteEngine(engineID, self.namespace)

    def onReport(self, request, engineID):
        with self.lock:
            sendAll = self.state.onReport(engineID)

            with self.activeLock:
                request.send(engineID)
                heapq.heapify(self.active)

            if sendAll:
                while self.unsent:
                    reference = self.unsent.pop()
                    request = reference()

                    if request is not None:
                        with self.activeLock:
                            request.send(engineID)
                            heapq.heappush(self.active, reference)

    def processResponse(self, request, response):
        with self.lock:
            auth = response.securityLevel.auth
            engineID = response.securityEngineID
            if self.state.onResponse(engineID, auth):
                self.engineID = engineID

            return True

    def sendPdu(self, pdu, handle, engineID, user, securityLevel):
        self.dispatcher.sendPdu(
            self.locator,
            MessageProcessingModel.SNMPv3,
            pdu,
            handle,
            engineID,
            user,
            securityLevel=securityLevel,
            securityModel=SecurityModel.USM,
        )

    def sendRequest(self, pdu, securityLevel=None,
                    user=None, wait=None, **kwargs):
        if securityLevel is None:
            securityLevel = self.defaultSecurityLevel

        if user is None:
            user = self.defaultUserName

        if wait is None:
            wait = self.autowait

        pdu.requestID = self.generateRequestID()
        request = Request(pdu, self, user, securityLevel, **kwargs)
        reference = ComparableWeakReference(request, self.drop)

        with self.lock:
            if self.state.onRequest(securityLevel.auth):
                with self.activeLock:
                    request.send(self.engineID)
                    heapq.heappush(self.active, reference)
            else:
                self.unsent.appendleft(reference)

        if wait:
            return request.wait()
        else:
            return request

    def get(self, *oids, **kwargs):
        pdu = GetRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def getBulk(self, *oids, nonRepeaters=0, maxRepetitions=0, **kwargs):
        pdu = GetBulkRequestPDU(
            *oids,
            nonRepeaters=nonRepeaters,
            maxRepetitions=maxRepetitions,
        )

        return self.sendRequest(pdu, **kwargs)

    def getNext(self, *oids, **kwargs):
        pdu = GetNextRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def set(self, *varbinds, **kwargs):
        varbinds = (VarBind(*varbind) for varbind in varbinds)
        pdu = SetRequestPDU(*varbinds)
        return self.sendRequest(pdu, **kwargs)
