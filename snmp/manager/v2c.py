__all__ = ["SNMPv2cManager"]

import heapq
import math
import threading
import time

from snmp.asn1 import *
from snmp.dispatcher import *
from snmp.manager import *
from snmp.message import *
from snmp.smi import *
from snmp.pdu import *
from snmp.transport import *
from snmp.typing import *
from snmp.utils import *

class Request(RequestHandle[Message]):
    def __init__(self,
        pdu: AnyPDU,
        manager: "SNMPv2cManager[Any]",
        community: bytes,
        timeout: float = 10.0,
        refreshPeriod: float = 1.0,
    ) -> None:
        now = time.time()

        self.community = community
        self.manager = manager
        self.pdu = pdu

        self.callback: Optional[Callable[[int], None]] = None
        self.event = threading.Event()
        self.response: Optional[Message] = None

        self.expiration = now + timeout
        self._nextRefresh = self.expiration
        self.period = refreshPeriod

    def __del__(self) -> None:
        if self.callback is not None:
            self.close()

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
        assert self.callback is not None
        self.callback(self.pdu.requestID)
        self.callback = None

    def addCallback(self,
        callback: Callable[[int], None],
        requestID: int,
    ) -> None:
        assert requestID == self.pdu.requestID
        assert self.callback is None

        self.callback = callback

    def push(self, response: Message) -> None:
        self.response = response
        self.event.set()

    # Always update self.nextRefresh right before calling this method
    def reallySend(self) -> None:
        self.manager.sendPdu(self.pdu, self, self.community)

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

    def send(self) -> None:
        now = time.time()
        self.nextRefresh = now + self.period
        self.reallySend()

    def wait(self) -> VarBindList:
        pdu: Optional[ResponsePDU] = None
        while not self.expired:
            timeout = self.manager.refresh()
            if self.event.wait(timeout=timeout):
                assert self.response is not None
                pdu = cast(ResponsePDU, self.response.pdu)
                break

        self.close()
        if pdu is None:
            raise Timeout()
        else:
            if pdu.errorStatus:
                raise ErrorResponse(pdu.errorStatus, pdu.errorIndex, self.pdu)
            else:
                return pdu.variableBindings

T = TypeVar("T")
class SNMPv2cManager(Generic[T]):
    def __init__(self,
        dispatcher: Dispatcher[T],
        channel: TransportChannel[T],
        community: bytes,
        autowait: bool = True,
    ):
        self.autowait = autowait
        self.channel = channel

        self.dispatcher = dispatcher
        self.defaultCommunity = community

        self.lock = threading.Lock()
        self.requests: List[ComparableWeakRef[Request, float]] = []

    def refresh(self) -> Optional[float]:
        while self.requests:
            with self.lock:
                reference = self.requests[0]
                request = reference()

                if request is None:
                    wait = None
                else:
                    wait = request.refresh()

                if wait is None:
                    heapq.heappop(self.requests)
                    continue
                elif wait > 0.0:
                    return wait
                else:
                    heapq.heapreplace(self.requests, reference)

        return None

    def sendPdu(self,
        pdu: AnyPDU,
        handle: Request,
        community: bytes,
    ) -> None:
        self.dispatcher.sendPdu(
            self.channel,
            MessageProcessingModel.SNMPv2c,
            pdu,
            handle,
            community,
        )

    def sendRequest(self,
        pdu: AnyPDU,
        community: Optional[bytes] = None,
        wait: Optional[bool] = None,
        **kwargs: Any,
    ) -> Union[Request, VarBindList]:
        if community is None:
            community = self.defaultCommunity

        if wait is None:
            wait = self.autowait

        request = Request(pdu, self, community, **kwargs)
        reference = ComparableWeakRef(request, key=lambda r: r.nextRefresh)

        with self.lock:
            heapq.heappush(self.requests, reference)
            request.send()

        if wait:
            return request.wait()
        else:
            return request

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
