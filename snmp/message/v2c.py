import threading
import weakref

from snmp.ber import *
from snmp.exception import *
from snmp.message import *
from snmp.pdu import *
from snmp.requests import *
from snmp.typing import *

pduTypes = {
    cls.TAG: cls for cls in cast(Tuple[Type[AnyPDU], ...], (
        GetRequestPDU,
        GetNextRequestPDU,
        ResponsePDU,
        SetRequestPDU,
        GetBulkRequestPDU,
        InformRequestPDU,
        SNMPv2TrapPDU,
        ReportPDU,
    ))
}

class LateResponse(IncomingMessageError):
    pass

class ResponseMismatch(IncomingMessageError):
    pass

class CacheEntry:
    def __init__(self,
        handle: RequestHandle[Message],
        community: bytes,
    ) -> None:
        self.community = community
        self.handle = weakref.ref(handle)

class SNMPv2cMessageProcessor(MessageProcessor[Message, AnyPDU]):
    VERSION = ProtocolVersion.SNMPv2c

    def __init__(self) -> None:
        self.cacheLock = threading.Lock()
        self.requestIDAuthority = RequestIDAuthority()
        self.outstanding: Dict[int, CacheEntry] = {}

    def cache(self, entry: CacheEntry) -> int:
        with self.cacheLock:
            requestID = self.requestIDAuthority.reserve()
            assert requestID not in self.outstanding
            self.outstanding[requestID] = entry
            return requestID

    def retrieve(self, requestID: int) -> CacheEntry:
        with self.cacheLock:
            return self.outstanding[requestID]

    def uncache(self, requestID: int) -> None:
        with self.cacheLock:
            try:
                del self.outstanding[requestID]
            except KeyError:
                pass
            else:
                self.requestIDAuthority.release(requestID)

    def prepareDataElements(self,
        msg: Asn1Data,
    ) -> Tuple[Message, RequestHandle[Message]]:
        message = Message.decodeExact(msg, types=pduTypes)

        if isinstance(message.pdu, ResponsePDU):
            try:
                entry = self.retrieve(message.pdu.requestID)
            except KeyError as err:
                errmsg = f"Unknown requestID: {message.pdu.requestID}"
                raise ResponseMismatch(errmsg) from err

            handle = entry.handle()
            if handle is None:
                self.uncache(message.pdu.requestID)
                raise LateResponse("Handle has already been released")

            if entry.community != message.community:
                raise ResponseMismatch(f"Community does not match request")
        else:
            raise UnsupportedFeature("Received a non-response PDU type")

        return message, handle

    def prepareOutgoingMessage(self,
        pdu: AnyPDU,
        handle: RequestHandle[Message],
        community: bytes,
    ) -> bytes:
        if pdu.requestID == 0:
            cacheEntry = CacheEntry(handle, community)
            pdu.requestID = self.cache(cacheEntry)
            handle.addCallback(self.uncache, pdu.requestID)

        return Message(self.VERSION, community, pdu).encode()
