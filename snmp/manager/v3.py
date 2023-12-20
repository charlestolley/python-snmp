__all__ = ["SNMPv3UsmManager"]

from abc import abstractmethod
from collections import deque

import heapq
import math
import threading
import time
import weakref

from snmp.asn1 import *
from snmp.dispatcher import *
from snmp.exception import *
from snmp.message import *
from snmp.message.v3 import *
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.usm import *
from snmp.smi import *
from snmp.transport import *
from snmp.typing import *
from snmp.utils import *
from . import *

usmStats = OID.parse("1.3.6.1.6.3.15.1.1")
usmStatsUnsupportedSecLevels        = usmStats.extend(1, 0)
usmStatsNotInTimeWindowsInstance    = usmStats.extend(2, 0)
usmStatsUnknownUserNames            = usmStats.extend(3, 0)
usmStatsUnknownEngineIDsInstance    = usmStats.extend(4, 0)
usmStatsWrongDigests                = usmStats.extend(5, 0)
usmStatsDecryptionErrors            = usmStats.extend(6, 0)

class UnhandledReport(SNMPException):
    pass

class UnrecognizedReport(UnhandledReport):
    def __init__(self, varbind: VarBind) -> None:
        super().__init__(f"Remote Engine sent this Report: \"{varbind}\"")
        self.name = varbind.name
        self.value = varbind.value

class UsmStatsReport(UnhandledReport):
    def __init__(self, errmsg: Any, varbind: VarBind) -> None:
        super().__init__(errmsg)
        self.name = varbind.name
        self.value = varbind.value

class UnsupportedSecurityLevelReport(UsmStatsReport):
    def __init__(self, message: SNMPv3Message, varbind: VarBind) -> None:
        securityLevel = message.header.flags.securityLevel
        errmsg = f"Remote Engine does not support {securityLevel}"
        super().__init__(errmsg, varbind)

class UnknownUserNameReport(UsmStatsReport):
    def __init__(self, message: SNMPv3Message, varbind: VarBind) -> None:
        assert message.securityName is not None
        userName = message.securityName.decode()
        errmsg = f"Remote Engine does not recognize user \"{userName}\""
        super().__init__(errmsg, varbind)

class WrongDigestReport(UsmStatsReport):
    def __init__(self, message: SNMPv3Message, varbind: VarBind) -> None:
        assert message.securityName is not None
        userName = message.securityName.decode()

        errmsg = (
            "Remote Engine reported that your request failed authentication"
            f"; make sure \"{userName}\" is using the correct credentials"
        )

        super().__init__(errmsg, varbind)

class DecryptionErrorReport(UsmStatsReport):
    def __init__(self, message: SNMPv3Message, varbind: VarBind) -> None:
        errmsg = "Remote Engine was unable to decrypt your request"
        super().__init__(errmsg, varbind)

class DiscoveryError(IncomingMessageError):
    pass

class State:
    def __init__(self, arg: Union["SNMPv3UsmManager[Any]", "State"]):
        self.manager: "SNMPv3UsmManager[Any]"
        if isinstance(arg, State):
            self.manager = arg.manager
        else:
            self.manager = weakref.proxy(arg)

    @abstractmethod
    def onInactive(self) -> None:
        ...

    @abstractmethod
    def onRequest(self, auth: bool) -> bool:
        ...

    @abstractmethod
    def onReport(self, engineID: bytes) -> bool:
        ...

    @abstractmethod
    def onResponse(self, engineID: bytes, auth: bool) -> bool:
        ...

# User did not provide an engine ID, and
# has not yet attempted to send any requests
class Inactive(State):
    def onInactive(self) -> None:
        pass

    def onRequest(self, auth: bool) -> bool:
        self.manager.nextState = WaitForDiscovery(self)
        return True

    def onReport(self, engineID: bytes) -> bool:
        errmsg = "Received a report where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

    def onResponse(self, engineID: bytes, auth: bool) -> bool:
        errmsg = "Received a response where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

# User provided an engine ID, but has not yet sent any requests
class Unsynchronized(State):
    def onInactive(self) -> None:
        pass

    def onRequest(self, auth: bool) -> bool:
        self.manager.nextState = Synchronizing(self)
        return True

    def onReport(self, engineID: bytes) -> bool:
        errmsg = "Received a report where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

    def onResponse(self, engineID: bytes, auth: bool) -> bool:
        errmsg = "Received a response where no request should have been sent"
        raise SNMPLibraryBug(errmsg)

# User did not provide an engine ID, and the Manager has not
# yet received any communication from the remote engine.
class WaitForDiscovery(State):
    def onInactive(self) -> None:
        self.manager.nextState = Inactive(self)

    def onRequest(self, auth: bool) -> bool:
        return False

    def onReport(self, engineID: bytes) -> bool:
        self.manager.nextState = TrustEveryResponse(self)
        return True

    def onResponse(self, engineID: bytes, auth: bool) -> bool:
        errmsg = "Received a ResponsePDU in response to a discovery message"
        raise DiscoveryError(errmsg)

# User provided engineID and has sent at least one request, but the
# Manager has not yet received any communication from the remote engine.
class Synchronizing(State):
    def onInactive(self) -> None:
        self.manager.nextState = Unsynchronized(self)

    def onRequest(self, auth: bool) -> bool:
        return not auth

    def onReport(self, engineID: bytes) -> bool:
        if self.manager.engineID == engineID:
            self.manager.nextState = RequireAuthentication(self)
            return True
        else:
            return False

    def onResponse(self, engineID: bytes, auth: bool) -> bool:
        if auth or self.manager.engineID == engineID:
            self.manager.nextState = RequireAuthentication(self)
            return True
        else:
            return False

class TrustEveryResponse(State):
    def onInactive(self) -> None:
        pass

    def onRequest(self, auth: bool) -> bool:
        return True

    def onReport(self, engineID: bytes) -> bool:
        return False

    def onResponse(self, engineID: bytes, auth: bool) -> bool:
        if auth:
            self.manager.nextState = RequireAuthentication(self)

        return True

class RequireAuthentication(State):
    def onInactive(self) -> None:
        pass

    def onRequest(self, auth: bool) -> bool:
        return True

    def onReport(self, engineID: bytes) -> bool:
        return False

    def onResponse(self, engineID: bytes, auth: bool) -> bool:
        return auth

class SharedBool:
    def __init__(self, value: bool) -> None:
        self.value = value

    def __bool__(self) -> bool:
        return self.value

    def makeTrue(self) -> None:
        self.value = True

    def makeFalse(self) -> None:
        self.value = False

class RequestMessage(RequestHandle[SNMPv3Message]):
    USM_EXCEPTION_TYPES = {
        usmStatsUnsupportedSecLevels:   UnsupportedSecurityLevelReport,
        usmStatsUnknownUserNames:       UnknownUserNameReport,
        usmStatsWrongDigests:           WrongDigestReport,
        usmStatsDecryptionErrors:       DecryptionErrorReport,
    }

    def __init__(self, request: "Request", synchronized: SharedBool) -> None:
        self.request = weakref.proxy(request)
        self.messageID: Optional[int] = None
        self.callback: Optional[Callable[[int], None]] = None

        self.synchronized = synchronized

    def addCallback(self, func: Callable[[int], None], msgID: int) -> None:
        self.callback = func
        self.messageID = msgID

    def push(self, response: SNMPv3Message) -> None:
        assert response.scopedPDU is not None
        pdu = response.scopedPDU.pdu

        if isinstance(pdu, ReportPDU):
            securityLevel = response.header.flags.securityLevel
            varbind = pdu.variableBindings[0]

            oid = varbind.name
            if oid == usmStatsUnknownEngineIDsInstance:
                self.request.processUnknownEngineID(response.securityEngineID)
            elif oid == usmStatsNotInTimeWindowsInstance:
                if not self.synchronized:
                    engineID = response.securityEngineID
                    self.request.processNotInTimeWindow(engineID)
            else:
                exception: UnhandledReport

                try:
                    exc_type = self.USM_EXCEPTION_TYPES[oid]
                except KeyError:
                    exception = UnrecognizedReport(varbind)
                else:
                    exception = exc_type(response, varbind)

                auth = response.header.flags.authFlag
                self.request.processException(exception, auth)
        else:
            self.request.processResponse(cast(ResponsePDU, response))

    def close(self) -> None:
        if self.callback is not None:
            assert self.messageID is not None
            self.callback(self.messageID)
            self.callback = None

class Request:
    def __init__(self,
        pdu: AnyPDU,
        manager: "SNMPv3UsmManager[Any]",
        userName: bytes,
        securityLevel: SecurityLevel,
        timeout: float = 10.0,
        refreshPeriod: float = 1.0,
    ) -> None:
        now = time.time()

        self._engineID: Optional[bytes] = None
        self.synchronized = SharedBool(False)

        self.manager = manager
        self.pdu = pdu
        self.securityLevel = securityLevel
        self.userName = userName

        self.messages: Set[RequestMessage] = set()

        self.event = threading.Event()
        self.exception: Optional[UnhandledReport] = None
        self.response: Optional[SNMPv3Message] = None

        self.expiration = now + timeout
        self._nextRefresh = self.expiration
        self.period = refreshPeriod

    def __del__(self) -> None:
        self.close()

    @property
    def engineID(self) -> Optional[bytes]:
        return self._engineID

    @engineID.setter
    def engineID(self, engineID: Optional[bytes]) -> None:
        if engineID == self._engineID:
            return

        if engineID is not None:
            self.manager.registerRemoteEngine(engineID)

        if self._engineID is not None:
            self.manager.unregisterRemoteEngine(self._engineID)

        self._engineID = engineID

    @property
    def expired(self) -> bool:
        return self.expiration <= time.time()

    @property
    def nextRefresh(self) -> float:
        return self._nextRefresh

    @nextRefresh.setter
    def nextRefresh(self, value: float) -> None:
        self._nextRefresh = min(self.expiration, value)

    def close(self) -> None:
        while self.messages:
            self.messages.pop().close()

        self.engineID = None

    def processNotInTimeWindow(self, engineID: bytes) -> None:
        self.manager.onReport(self, engineID)
        self.synchronized.makeTrue()
        self.synchronized = SharedBool(False)

    def processUnknownEngineID(self, engineID: bytes) -> None:
        if engineID != self.engineID:
            self.manager.onReport(self, engineID)

    def processException(self, exception: UnhandledReport, auth: bool) -> None:
        if auth:
            if not self.event.is_set():
                self.exception = exception
                self.event.set()
        elif self.exception is None:
            self.exception = exception

    def processResponse(self, response: SNMPv3Message) -> None:
        #if random.randint(1, 3) % 3 != 0:
        #    return

        if self.manager.processResponse(self, response):
            if not self.event.is_set():
                self.response = response
                self.event.set()

    # Always update self.nextRefresh right before calling this method
    def reallySend(self, engineID: Optional[bytes] = None) -> None:
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

    def refresh(self) -> Optional[float]:
        if self.event.is_set():
            return None

        now = time.time()
        timeToNextRefresh = self.nextRefresh - now

        if timeToNextRefresh <= 0.0:
            if self.expiration <= now:
                return None

            # Calculating it like this mitigates over-delay
            periodsElapsed = math.ceil(-timeToNextRefresh / self.period)
            self.nextRefresh += periodsElapsed * self.period
            self.reallySend()
            return 0.0
        else:
            return timeToNextRefresh

    def send(self, engineID: Optional[bytes] = None) -> None:
        now = time.time()
        self.nextRefresh = now + self.period
        self.reallySend(engineID)

    def wait(self) -> VarBindList:
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
                assert self.response.scopedPDU is not None
                pdu = cast(ResponsePDU, self.response.scopedPDU.pdu)
                if pdu.errorStatus:
                    raise ErrorResponse(
                        pdu.errorStatus,
                        pdu.errorIndex,
                        self.pdu,
                    )
                else:
                    return pdu.variableBindings
            else:
                if self.exception is not None:
                    raise self.exception
                else:
                    raise Timeout()
        finally:
            self.close()

T = TypeVar("T")
class SNMPv3UsmManager(Generic[T]):
    def __init__(self,
        dispatcher: Dispatcher[T],
        usm: UserBasedSecurityModule,
        channel: TransportChannel[T],
        namespace: str,
        defaultUserName: bytes,
        defaultSecurityLevel: SecurityLevel,
        engineID: Optional[bytes] = None,
        autowait: bool = True,
    ) -> None:

        # Used by @property
        self._engineID: Optional[bytes] = None

        # Read-only fields
        self.channel = channel
        self.namespace = namespace
        self.defaultUserName = defaultUserName
        self.defaultSecurityLevel = defaultSecurityLevel
        self.autowait = autowait

        self.dispatcher = dispatcher
        self.usm = usm

        self.generator = self.newGenerator()

        # protects self.active
        self.activeLock = threading.Lock()
        self.active: List[ComparableWeakRef[Request, float]] = []

        # protects self.unsent, self.state, and self.engineID
        self.lock = threading.Lock()
        self.unsent: Deque[ComparableWeakRef[Request, float]] = deque()

        self.state: State
        self.nextState = None
        if engineID is None:
            self.state = Inactive(self)
        else:
            self.engineID = engineID
            self.state = Unsynchronized(self)

    def __del__(self) -> None:
        self.engineID = None

    @property
    def engineID(self) -> Optional[bytes]:
        return self._engineID

    @engineID.setter
    def engineID(self, engineID: Optional[bytes]) -> None:
        if engineID == self._engineID:
            return

        if engineID is not None:
            self.registerRemoteEngine(engineID)

        if self._engineID is not None:
            self.unregisterRemoteEngine(self._engineID)

        self._engineID = engineID

    def generateRequestID(self) -> int:
        requestID = next(self.generator)

        if requestID == 0:
            self.generator = self.newGenerator()
            requestID = next(self.generator)

        return requestID

    def newGenerator(self) -> NumberGenerator:
        return NumberGenerator(32)

    def poke(self) -> bool:
        active = False
        with self.lock:
            self.state.onInactive()
            self.updateState()

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

                        self.updateState()
                    else:
                        self.unsent.appendleft(reference)

        return active

    def refresh(self) -> float:
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
                else:
                    active = False

            if not active:
                active = self.poke()

        return 0.0

    def registerRemoteEngine(self, engineID: bytes) -> None:
        if not self.usm.registerRemoteEngine(engineID, self.namespace):
            errmsg = f"Failed to register engineID {engineID!r}"

            if self.namespace:
                errmsg += f" under namespace \"{self.namespace}\""

            raise DiscoveryError(errmsg)

    def unregisterRemoteEngine(self, engineID: bytes) -> None:
        self.usm.unregisterRemoteEngine(engineID, self.namespace)

    def onReport(self, request: Request, engineID: bytes) -> None:
        with self.lock:
            sendAll = self.state.onReport(engineID)

            with self.activeLock:
                request.send(engineID)
                heapq.heapify(self.active)

            if sendAll:
                self.updateState()
                while self.unsent:
                    reference = self.unsent.pop()
                    req = reference()

                    if req is not None:
                        with self.activeLock:
                            req.send(engineID)
                            heapq.heappush(self.active, reference)

    def processResponse(self,
        request: Request,
        response: SNMPv3Message,
    ) -> bool:
        with self.lock:
            auth = response.header.flags.authFlag
            engineID = response.securityEngineID
            assert engineID is not None
            if self.state.onResponse(engineID, auth):
                self.engineID = engineID
                self.updateState()

            return True

    def sendPdu(self,
        pdu: AnyPDU,
        handle: RequestMessage,
        engineID: bytes,
        user: bytes,
        securityLevel: SecurityLevel,
    ) -> None:
        self.dispatcher.sendPdu(
            self.channel,
            MessageProcessingModel.SNMPv3,
            pdu,
            handle,
            engineID,
            user,
            securityLevel=securityLevel,
            securityModel=SecurityModel.USM,
        )

    def sendRequest(self,
        pdu: AnyPDU,
        securityLevel: Optional[SecurityLevel] = None,
        user: Optional[bytes] = None,
        wait: Optional[bool] = None,
        **kwargs: Any,
    ) -> Union[Request, VarBindList]:
        if securityLevel is None:
            securityLevel = self.defaultSecurityLevel

        if user is None:
            user = self.defaultUserName

        if wait is None:
            wait = self.autowait

        pdu.requestID = self.generateRequestID()
        request = Request(pdu, self, user, securityLevel, **kwargs)
        reference = ComparableWeakRef(request, key=lambda r: r.nextRefresh)

        with self.lock:
            if self.state.onRequest(securityLevel.auth):
                with self.activeLock:
                    request.send(self.engineID)
                    heapq.heappush(self.active, reference)

                self.updateState()
            else:
                self.unsent.appendleft(reference)

        if wait:
            return request.wait()
        else:
            return request

    def updateState(self) -> None:
        if self.nextState is not None:
            self.state = self.nextState
            self.nextState = None

    def get(self,
        *oids: Union[str, OID],
        **kwargs: Any,
    ) -> Union[Request, VarBindList]:
        pdu = GetRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def getBulk(self,
        *oids: Union[str, OID],
        nonRepeaters: int = 0,
        maxRepetitions: int = 0,
        **kwargs: Any,
    ) -> Union[Request, VarBindList]:
        pdu = GetBulkRequestPDU(
            *oids,
            nonRepeaters=nonRepeaters,
            maxRepetitions=maxRepetitions,
        )

        return self.sendRequest(pdu, **kwargs)

    def getNext(self,
        *oids: Union[str, OID],
        **kwargs: Any,
    ) -> Union[Request, VarBindList]:
        pdu = GetNextRequestPDU(*oids)
        return self.sendRequest(pdu, **kwargs)

    def set(self,
        *varbinds: Union[
            Tuple[
                Union[str, OID],
                Optional[ASN1],
            ],
            VarBind,
        ],
        **kwargs: Any,
    ) -> Union[Request, VarBindList]:
        vbList = (VarBind(*varbind) for varbind in varbinds)
        pdu = SetRequestPDU(*vbList)
        return self.sendRequest(pdu, **kwargs)
