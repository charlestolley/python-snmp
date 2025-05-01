__all__ = ["SNMPv3UsmManager"]

from collections import deque

import weakref

from snmp.asn1 import *
from snmp.dispatcher import *
from snmp.exception import *
from snmp.message import *
from snmp.pdu import *
from snmp.scheduler import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.usm import *
from snmp.smi import *
from snmp.transport import *
from snmp.typing import *
from snmp.utils import *
from snmp.v3.message import SNMPv3Message
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
        assert message.securityName.userName is not None
        userName = message.securityName.userName.decode()
        errmsg = f"Remote Engine does not recognize user \"{userName}\""
        super().__init__(errmsg, varbind)

class WrongDigestReport(UsmStatsReport):
    def __init__(self, message: SNMPv3Message, varbind: VarBind) -> None:
        assert message.securityName.userName is not None
        userName = message.securityName.userName.decode()

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

    def onInactive(self) -> None:
        raise NotImplementedError()

    def onRequest(self, auth: bool) -> bool:
        raise NotImplementedError()

    def onReport(self, engineID: bytes) -> bool:
        raise NotImplementedError()

    def onResponse(self, engineID: bytes, auth: bool) -> bool:
        raise NotImplementedError()

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
        refreshPeriod: float = 1.0,
    ) -> None:
        self._engineID: Optional[bytes] = None
        self.synchronized = SharedBool(False)

        self.manager = manager
        self.pdu = pdu
        self.securityLevel = securityLevel
        self.userName = userName

        self.messages: Set[RequestMessage] = set()
        self.exception: Optional[UnhandledReport] = None
        self.response: Optional[SNMPv3Message] = None

        self._expired = False
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
    def active(self) -> bool:
        return self.response is None and not self.expired

    @property
    def expired(self) -> bool:
        return self._expired

    @expired.setter
    def expired(self, value: bool) -> None:
        if self.active:
            self._expired = value

            if not self.active:
                self.close()

            self.manager.deactivate(self)

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
            if self.active:
                self.exception = exception
                self.expired = True
        elif self.exception is None:
            self.exception = exception

    def processResponse(self, response: SNMPv3Message) -> None:
        #if random.randint(1, 3) % 3 != 0:
        #    return

        if self.manager.processResponse(self, response):
            if self.active:
                self.response = response

    def send(self, engineID: Optional[bytes] = None) -> None:
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

    def wait(self) -> VarBindList:
        try:
            pdu = None
            while self.active:
                try:
                    self.manager.scheduler.wait()
                except KeyboardInterrupt as interrupt:
                    if self.exception is not None:
                        raise self.exception from interrupt
                    else:
                        raise

            if self.response is None:
                if self.exception is not None:
                    raise self.exception
                else:
                    raise Timeout()
            else:
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
        finally:
            self.close()

T = TypeVar("T")
class SNMPv3UsmManager(Generic[T]):
    def __init__(self,
        scheduler: Scheduler,
        dispatcher: Dispatcher,
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
        self.scheduler = scheduler
        self.usm = usm

        self.generator = self.newGenerator()

        self.active = {}
        self.unsent = deque()

        self.state: State
        self.nextState = None
        if engineID is None:
            self.state = Inactive(self)
        else:
            self.engineID = engineID
            self.state = Unsynchronized(self)

    class ExpireTask(SchedulerTask):
        def __init__(self, request):
            self.request = request

        def run(self):
            self.request.expired = True

    class SendTask(SchedulerTask):
        def __init__(self, request, engineID):
            self.cancelled = False
            self.request = request
            self.engineID = engineID

        def cancel(self):
            self.cancelled = True

        def run(self):
            if self.request.active and not self.cancelled:
                self.request.send(self.engineID)
                return self

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

    def deactivate(self, request):
        del self.active[request.pdu.requestID]

        if not self.active:
            self.poke()

    def poke(self) -> bool:
        self.state.onInactive()
        self.updateState()

        unsent = self.unsent
        self.unsent = deque()
        while unsent:
            reference = unsent.pop()
            request = reference()

            if request is not None:
                if self.state.onRequest(request.securityLevel.auth):
                    task = self.SendTask(request, self.engineID)
                    self.active[request.pdu.requestID] = task
                    self.scheduler.schedule(task, period=request.period)
                    self.updateState()
                else:
                    self.unsent.appendleft(reference)

    def registerRemoteEngine(self, engineID: bytes) -> None:
        if not self.usm.registerRemoteEngine(engineID, self.namespace):
            errmsg = f"Failed to register engineID {engineID!r}"

            if self.namespace:
                errmsg += f" under namespace \"{self.namespace}\""

            raise DiscoveryError(errmsg)

    def unregisterRemoteEngine(self, engineID: bytes) -> None:
        self.usm.unregisterRemoteEngine(engineID, self.namespace)

    def onReport(self, request: Request, engineID: bytes) -> None:
        sendAll = self.state.onReport(engineID)

        self.active[request.pdu.requestID].cancel()
        task = self.SendTask(request, engineID)
        self.active[request.pdu.requestID] = task
        self.scheduler.schedule(task, period=request.period)

        if sendAll:
            self.updateState()
            while self.unsent:
                reference = self.unsent.pop()
                req = reference()

                if req is not None:
                    task = self.SendTask(req, engineID)
                    self.active[req.pdu.requestID] = task
                    self.scheduler.schedule(task, period=req.period)

    def processResponse(self,
        request: Request,
        response: SNMPv3Message,
    ) -> bool:
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
            ProtocolVersion.SNMPv3,
            pdu,
            handle,
            engineID,
            user,
            self.namespace,
            securityLevel=securityLevel,
            securityModel=SecurityModel.USM,
        )

    def sendRequest(self,
        pdu: AnyPDU,
        securityLevel: Optional[SecurityLevel] = None,
        user: Optional[bytes] = None,
        wait: Optional[bool] = None,
        timeout: float = 10.0,
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
        self.scheduler.schedule(self.ExpireTask(request), timeout)
        reference = weakref.ref(request)

        if self.state.onRequest(securityLevel.auth):
            task = self.SendTask(request, self.engineID)
            self.active[request.pdu.requestID] = task
            self.scheduler.schedule(task, period=request.period)
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
