__all__ = ["SNMPv3UsmManager"]

import heapq
import threading
import weakref

from snmp.dispatcher import *
from snmp.exception import *
from snmp.message import *
from snmp.pdu.v2 import *
from snmp.security import *
from snmp.security.levels import *
from snmp.types import *
from snmp.utils import *
from . import *

usmStatsNotInTimeWindowsInstance = OID.parse("1.3.6.1.6.3.15.1.1.2.0")
usmStatsUnknownEngineIDsInstance = OID.parse("1.3.6.1.6.3.15.1.1.4.0")

class State:
    def __init__(self, arg):
        if isinstance(arg, State):
            self._manager = arg._manager
        else:
            self._manager = weakref.ref(arg)

    @property
    def manager(self):
        manager = self._manager()
        assert manager is not None
        return manager

# User did not provide an engine ID, and
# has not yet attempted to send any requests
class Inactive(State):
    def onRequest(self, request):
        request.send()
        self.manager.state = WaitForDiscovery(self)

    def onReport(self, request, response):
        errmsg = "Received a report where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

    def onResponse(self, request, response):
        errmsg = "Received a response where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

# User provided an engine ID, but has not yet sent any requests
class Unsynchronized(State):
    def onRequest(self, request):
        request.send(self.manager.engineID)
        self.manager.state = Synchronizing(self)

    def onReport(self, request, response):
        errmsg = "Received a report where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

    def onResponse(self, request, response):
        errmsg = "Received a response where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

# User did not provide an engine ID, and the Manager has not
# yet received any communication from the remote engine.
class WaitForDiscovery(State):
    def onRequest(self, request):
        pass

    def onReport(self, request, response):
        engineID = response.securityEngineID

        try:
            self.manager.engineID = engineID
        except ValueError as err:
            print(err)
            return

        for entry in self.manager.requests:
            request = entry.request()
            if request is not None:
                request.send(engineID)

        self.manager.state = TrustEveryResponse(self)

    def onResponse(self, request, response):
        pass

# User provided and engineID and has sent at least one request, but the
# Manager has not yet received any communication from the remote engine.
class Synchronizing(State):
    def onRequest(self, request):
        if not request.securityLevel.auth:
            request.send(self.manager.engineID)

    def onReport(self, request, response):
        oid = response.data.pdu.variableBindings[0].name
        if oid == usmStatsUnknownEngineIDsInstance:
            try:
                request.send(response.securityEngineID)
            except ValueError:
                return
        elif response.securityLevel.auth:
            if response.securityEngineID != self.manager.engineID:
                self.manager.engineID = response.securityEngineID

            for entry in self.manager.requests:
                request = entry.request()
                if request is not None and request.securityLevel.auth:
                    request.send(self.manager.engineID)

            self.manager.state = RequireAuthentication(self)

    def onResponse(self, request, response):
        if response.securityLevel.auth:
            if response.securityEngineID != self.manager.engineID:
                self.manager.engineID = response.securityEngineID

        answered = request
        for entry in self.manager.requests:
            r = entry.request()
            if r is not None and r is not request and r.securityLevel.auth:
                r.send(self.manager.engineID)

        self.manager.state = RequireAuthentication(self)

class TrustEveryResponse(State):
    def onRequest(self, request):
        request.send(self.manager.engineID)

    def onReport(self, request, response):
        oid = response.data.pdu.variableBindings[0].name
        if oid == usmStatsUnknownEngineIDsInstance:
            try:
                request.send(response.securityEngineID)
            except ValueError:
                return

        if response.securityLevel.auth:
            if response.securityEngineID != self.manager.engineID:
                self.manager.engineID = response.securityEngineID
            self.manager.state = RequireAuthentication(self)

    def onResponse(self, request, response):
        if response.securityEngineID != self.manager.engineID:
            try:
                self.manager.engineID = response.securityEngineID
            except ValueError:
                return

        if response.securityLevel.auth:
            self.manager.state = RequireAuthentication(self)

class RequireAuthentication(State):
    def onRequest(self, request):
        request.send(self.manager.engineID)

    def onReport(self, request, response):
        oid = response.data.pdu.variableBindings[0].name
        if oid == usmStatsUnknownEngineIDsInstance:
            try:
                request.send(response.securityEngineID)
            except ValueError:
                return
        elif response.securityLevel.auth:
            if response.securityEngineID != self.manager.engineID:
                self.manager.engineID = response.securityEngineID

            if oid == usmStatsNotInTimeWindowsInstance:
                request.send(self.manager.engineID)

    def onResponse(self, request, response):
        if response.securityLevel.auth:
            if response.securityEngineID != self.manager.engineID:
                self.manager.engineID = response.securityEngineID

class Request(Dispatcher.Handle):
    def __init__(self, pdu, manager, userName, securityLevel):
        self._engineID = None

        self.manager = manager
        self.pdu = pdu
        self.securityLevel = securityLevel
        self.userName = userName

        self.callback = None
        self.messages = set()

        self.event = threading.Event()
        self.expired = False
        self.fulfilled = False
        self.response = None

    def __del__(self):
        if self.callback is not None:
            self.close()

    @property
    def engineID(self):
        return self._engineID

    @engineID.setter
    def engineID(self, engineID):
        if engineID == self._engineID:
            return

        localEngine = self.manager.localEngine
        namespace =  self.manager.namespace

        if engineID is not None:
            if not localEngine.registerRemoteEngine(engineID, namespace):
                errmsg = "Failed to register engineID {} under namespace \"{}\""
                raise ValueError(errmsg.format(engineID, namespace))

        if self._engineID != None:
            localEngine.unregisterRemoteEngine(self._engineID, namespace)

        self._engineID = engineID

    def close(self):
        for message in self.messages:
            self.callback(message)

        self.callback = None
        self.messages.clear()

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

    def send(self, engineID=None):
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

    def wait(self):
        pdu = None
        while not self.expired:
            timeout = self.manager.refresh()
            #print(f"Waiting for {timeout} seconds")
            if self.event.wait(timeout=timeout):
                pdu = self.response.data.pdu
                self.fulfilled = True
                break

        self.close()
        if pdu is None:
            raise Timeout()
        else:
            return pdu

class SNMPv3UsmManager:
    def __init__(self, engine, locator, namespace,
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

        self.generator = NumberGenerator(32)
        self.localEngine = engine

        # protects self.requests, self.state, and (implicitly) self.engineID
        self.lock = threading.Lock()
        self.requests = []

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
            if not self.localEngine.registerRemoteEngine(engineID, self.namespace):
                errmsg = "Failed to register engineID {} under namespace \"{}\""
                raise ValueError(errmsg.format(engineID, self.namespace))

        if self._engineID != None:
            self.localEngine.unregisterRemoteEngine(self._engineID, self.namespace)

        self._engineID = engineID

    def refresh(self):
        while True:
            with self.lock:
                entry = self.requests[0]
                result = entry.refresh()

                while result is None:
                    heapq.heappop(self.requests)
                    entry = self.requests[0]
                    result = entry.refresh()

                #print(f"Result = {result}")

                if result < 0:
                    heapq.heapreplace(self.requests, entry)
                else:
                    return result

    def processResponse(self, request, response):
        with self.lock:
            if isinstance(response.data.pdu, ReportPDU):
                self.state.onReport(request, response)
                return False
            else:
                self.state.onResponse(request, response)
                return True

    def sendPdu(self, pdu, handle, engineID, user, securityLevel):
        return self.localEngine.sendPdu(
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

        request = Request(pdu, self, user, securityLevel, **kwargs)

        with self.lock:
            heapq.heappush(self.requests, Repeater(request))
            self.state.onRequest(request)

        if wait:
            return request.wait()
        else:
            return request

    def get(self, *oids, **kwargs):
        pdu = GetRequestPDU(*oids, requestID=next(self.generator))
        return self.sendRequest(pdu, **kwargs)

    def getBulk(self, *oids, nonRepeaters=0, maxRepetitions=0, **kwargs):
        pdu = GetBulkRequestPDU(
            *oids,
            requestID=next(self.generator),
            nonRepeaters=nonRepeaters,
            maxRepetitions=maxRepetitions,
        )

        return self.sendRequest(pdu, **kwargs)

    def getNext(self, *oids, **kwargs):
        pdu = GetNextRequestPDU(*oids, requestID=next(self.generator))
        return self.sendRequest(pdu, **kwargs)

    def set(self, *varbinds, **kwargs):
        varbinds = (VarBind(*varbind) for varbind in varbinds)
        pdu = SetRequestPDU(*varbinds, requestID=next(self.generator))
        return self.sendRequest(pdu, **kwargs)
