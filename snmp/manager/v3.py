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

usmStatsNotInTimeWindowsInstance = OID.parse("1.3.6.1.6.3.15.1.1.2.0")
usmStatsUnknownEngineIDsInstance = OID.parse("1.3.6.1.6.3.15.1.1.4.0")

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

class Request(RequestHandle):
    def __init__(self, pdu, manager, userName, securityLevel,
                            timeout=10.0, refreshPeriod=1.0):
        now = time.time()

        self._engineID = None

        self.manager = manager
        self.pdu = pdu
        self.securityLevel = securityLevel
        self.userName = userName

        self.callback = None
        self.messages = set()

        self.event = threading.Event()
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

    @property
    def fulfilled(self):
        return self.event.is_set()

    def close(self):
        while self.messages:
            self.callback(self.messages.pop())

        self.callback = None
        self.engineID = None

    def addCallback(self, callback, msgID):
        if self.callback is None:
            self.callback = callback

        assert self.callback == callback
        self.messages.add(msgID)

    def push(self, response):
        #if random.randint(1, 3) % 3 != 0:
        #    return

        if self.manager.processResponse(self, response):
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

        return self.manager.sendPdu(pdu, self, engineID, user, securityLevel)

    def refresh(self):
        if self.fulfilled:
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
        pdu = None
        while not self.expired:
            timeout = self.manager.refresh()
            if self.event.wait(timeout=timeout):
                pdu = self.response.data.pdu
                break
        else:
            if self.fulfilled:
                pdu = self.response.data.pdu

        self.close()
        if pdu is None:
            raise Timeout()
        else:
            return pdu

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

    def processResponse(self, request, response):
        with self.lock:
            engineID = response.securityEngineID
            if isinstance(response.data.pdu, ReportPDU):
                oid = response.data.pdu.variableBindings[0].name
                if (oid == usmStatsUnknownEngineIDsInstance
                or  oid == usmStatsNotInTimeWindowsInstance):
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

                return False
            else:
                auth = response.securityLevel.auth
                if self.state.onResponse(engineID, auth):
                    self.engineID = engineID

                return True

    def sendPdu(self, pdu, handle, engineID, user, securityLevel):
        return self.dispatcher.sendPdu(
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
