import heapq
import math
import threading
import time
import weakref

from snmp.dispatcher import *
from snmp.exception import *
from snmp.message import *
from snmp.message.v3 import *
from snmp.pdu.v2 import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.usm import *
from snmp.transport import *
from snmp.transport.udp import *
from snmp.types import *
from snmp.utils import *

usmStatsNotInTimeWindowsInstance = OID.parse("1.3.6.1.6.3.15.1.1.2.0")
usmStatsUnknownEngineIDsInstance = OID.parse("1.3.6.1.6.3.15.1.1.4.0")

class Timeout(SNMPException):
    pass

class DiscoveryGuard:
    def __init__(self):
        self.namespace = None
        self.refCount = 0

    def claim(self, namespace):
        acquired = True
        initialized = True

        if namespace != self.namespace:
            if self.refCount:
                acquired = False
            else:
                self.namespace = namespace
                initialized = False

        if acquired:
            self.refCount += 1
            #print(f"claim  (\"{self.namespace}\"): refCount = {self.refCount}")

        return acquired, initialized

    def release(self, namespace):
        assert self.namespace == namespace
        assert self.refCount > 0
        self.refCount -= 1
        #print(f"release(\"{self.namespace}\"): refCount = {self.refCount}")
        return self.refCount == 0

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

class Repeater:
    def __init__(self, request, period=1.0, timeout=10.0):
        now = time.time()

        self.expiration = now + timeout
        self.nextRefresh = now + period
        self.period = period
        self.request = weakref.ref(request)

    def __lt__(a, b):
        return a.target < b.target

    def refresh(self):
        request = self.request()
        if request is None or request.fulfilled:
            return None

        now = time.time()
        if self.expiration <= now:
            request.expired = True
            return 0.0

        delta = self.target - now

        if delta < 0:
            self.nextRefresh += math.ceil(-delta / self.period) * self.period
            #print(f"Refreshing {id(self)} @ {now} ; nextRefresh = {self.nextRefresh} ; expiration = {self.expiration}")
            request.send()

        return delta

    @property
    def target(self):
        return min(self.expiration, self.nextRefresh)

class Request:
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

    def push(self, response, depth=0):
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
        self._engineID = None

        self.autowait = autowait
        self.generator = NumberGenerator(32)
        self.localEngine = engine
        self.locator = locator
        self.namespace = namespace

        self.defaultUserName = defaultUserName
        self.defaultSecurityLevel = defaultSecurityLevel

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
        return self.localEngine.dispatcher.sendPdu(
            self.locator.domain,
            self.locator.address,
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

class UserEntry:
    def __init__(self, defaultSecurityLevel, credentials):
        self.credentials = credentials
        self.defaultSecurityLevel = defaultSecurityLevel

class NameSpace:
    def __init__(self, defaultUserName):
        self.defaultUserName = defaultUserName
        self.users = {}

    def __iter__(self):
        return self.users.items().__iter__()

    def __contains__(self, key):
        return self.users.__contains__(key)

    def addUser(self, userName, *args, **kwargs):
        self.users[userName] = UserEntry(*args, **kwargs)

    def getUser(self, userName):
        return self.users[userName]

class Engine:
    TRANSPORTS = {
        cls.DOMAIN: cls for cls in [
            UdpTransport,
        ]
    }

    UNSUPPORTED = "{} is not supported at this time"

    def __init__(self, lockType=threading.Lock,
            defaultDomain=TransportDomain.UDP,
            defaultVersion=MessageProcessingModel.SNMPv3,
            defaultSecurityModel=SecurityModel.USM,
            autowait=True):

        self.defaultDomain = defaultDomain
        self.defaultVersion = defaultVersion
        self.defaultSecurityModel = defaultSecurityModel
        self.autowaitDefault = autowait
        self.dispatcher = Dispatcher(lockType=lockType)

        self.lock = lockType()
        self.lockType = lockType

        self.engines = {}
        self.namespaces = {}

        self.transports = set()
        self.mpv3 = None
        self.usm = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.shutdown()

    def shutdown(self):
        self.dispatcher.shutdown()

    def registerRemoteEngine(self, engineID, namespace):
        with self.lock:
            try:
                guard = self.engines[engineID]
            except KeyError:
                guard = DiscoveryGuard()
                self.engines[engineID] = guard

            acquired, initialized = guard.claim(namespace)
            if acquired and not initialized:
                space = self.namespaces[namespace]
                for userName, userEntry in space:
                    kwargs = self.localize(engineID, **userEntry.credentials)
                    self.usm.addUser(engineID, userName, **kwargs)

            return acquired

    def unregisterRemoteEngine(self, engineID, namespace):
        with self.lock:
            try:
                guard = self.engines[engineID]
            except KeyError:
                assert False, f"Engine {engineID} was never registered"
            else:
                if guard.release(namespace):
                    del self.engines[engineID]
                    #print(list(self.engines.keys()))

    @staticmethod
    def localize(engineID, authProtocol=None, authSecret=None,
                           privProtocol=None, privSecret=None):
        kwargs = dict()
        if authProtocol is not None:
            kwargs["authProtocol"] = authProtocol
            kwargs["authKey"] = authProtocol.localize(authSecret, engineID)

            if privProtocol is not None:
                kwargs["privProtocol"] = privProtocol
                kwargs["privKey"] = authProtocol.localize(privSecret, engineID)

        return kwargs

    def addUser(self, userName, authProtocol=None, authSecret=None,
            privProtocol=None, privSecret=None, secret=b"",
            default=False, defaultSecurityLevel=None, namespace=""):
        kwargs = dict()
        if authProtocol is None:
            maxSecurityLevel = noAuthNoPriv
        else:
            if privProtocol is None:
                maxSecurityLevel = authNoPriv
            else:
                maxSecurityLevel = authPriv
                kwargs["privProtocol"] = privProtocol
                kwargs["privSecret"] = privSecret or secret

            kwargs["authProtocol"] = authProtocol
            kwargs["authSecret"] = authSecret or secret

        if defaultSecurityLevel is None:
            defaultSecurityLevel = maxSecurityLevel
        elif defaultSecurityLevel > maxSecurityLevel:
            errmsg = "{} is required in order to support {}"
            param = "privProtocol" if maxSecurityLevel.auth else "authProtocol"
            raise ValueError(errmsg.format(param, defaultSecurityLevel))

        userName = userName.encode()

        with self.lock:
            try:
                space = self.namespaces[namespace]
            except KeyError:
                space = NameSpace(userName)
                self.namespaces[namespace] = space
            else:
                if userName in space:
                    errmsg = "User \"{}\" is already defined"

                    if namespace:
                        errmsg += " in namespace \"{}\"".format(namespace)

                    raise ValueError(errmsg.format(userName.decode()))

            if default:
                space.defaultUserName = userName

            space.addUser(userName, defaultSecurityLevel, kwargs)

    def connectTransport(self, transport):
        if transport.DOMAIN in self.transports:
            errmsg = "{} is already handled by a different transport object"
            raise ValueError(errmsg.format(transport.DOMAIN))
        elif transport.DOMAIN not in self.TRANSPORTS:
            raise ValueError(self.UNSUPPORTED.format(transport.DOMAIN))

        self.dispatcher.connectTransport(transport)
        self.transports.add(transport.DOMAIN)

    def v1Manager(self, locator):
        pass

    def v2cManager(self, locator, community=b"public"):
        pass

    def v3Manager(self, locator, securityModel=None, engineID=None,
            defaultUserName=None, namespace="", autowait=None):
        if securityModel is None:
            securityModel = self.defaultSecurityModel
        elif not isinstance(securityModel, SecurityModel):
            securityModel = SecurityModel(securityModel)

        try:
            space = self.namespaces[namespace]
        except KeyError as err:
            errmsg = f"No users defined in namespace \"{namespace}\""
            raise ValueError(errmsg) from err

        if defaultUserName is None:
            defaultUserName = space.defaultUserName

        try:
            defaultUser = space.getUser(defaultUserName)
        except KeyError as err:
            errmsg = "No such user in namespace \"{}\": \"{}\""
            raise ValueError(errmsg.format(namespace, defaultUserName)) from err
        else:
            defaultSecurityLevel = defaultUser.defaultSecurityLevel

        if autowait is None:
            autowait = self.autowaitDefault

        if locator.domain not in self.transports:
            transportClass = self.TRANSPORTS[locator.domain]
            self.dispatcher.connectTransport(transportClass())
            self.transports.add(locator.domain)

        if self.mpv3 is None:
            self.mpv3 = MessageProcessor(lockType=self.lockType)
            self.dispatcher.addMessageProcessor(self.mpv3)

        if securityModel == SecurityModel.USM:
            if self.usm is None:
                self.usm = SecurityModule(lockType=self.lockType)
                self.mpv3.secure(self.usm)

            return SNMPv3UsmManager(
                self,
                locator,
                namespace,
                defaultUserName,
                defaultSecurityLevel,
                engineID=engineID,
                autowait=autowait,
            )
        else:
            raise ValueError(self.UNSUPPORTED.format(str(securityModel)))

    def Manager(self, address, domain=None, version=None, **kwargs):
        if domain is None:
            domain = self.defaultDomain

        try:
            locator = self.TRANSPORTS[domain].Locator(address)
        except KeyError as err:
            raise ValueError(self.UNSUPPORTED.format(domain)) from err

        if version is None:
            version = self.defaultVersion
        elif not isinstance(version, MessageProcessingModel):
            version = MessageProcessingModel(version)

        if version == MessageProcessingModel.SNMPv3:
            return self.v3Manager(locator, **kwargs)
        elif version == MessageProcessingModel.SNMPv2:
            return self.v2Manager(locator, **kwargs)
        elif version == MessageProcessingModel.SNMPv1:
            return self.v1Manager(locator, **kwargs)
        else:
            raise ValueError(self.UNSUPPORTED.format(str(version)))
