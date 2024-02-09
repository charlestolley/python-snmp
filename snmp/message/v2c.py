import threading
import weakref

from snmp.ber import *
from snmp.exception import *
from snmp.message import *
from snmp.pdu import *
from snmp.typing import *
from snmp.utils import *

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

class CacheError(SNMPException):
    pass

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
        self.generator = self.newGenerator()
        self.outstanding: Dict[int, CacheEntry] = {}

    @staticmethod
    def newGenerator() -> NumberGenerator:
        return NumberGenerator(32)

    def cache(self, entry: CacheEntry) -> int:
        retry = 0
        while retry < 10:
            with self.cacheLock:
                requestID = next(self.generator)
                if requestID == 0:
                    self.generator = self.newGenerator()
                elif requestID not in self.outstanding:
                    self.outstanding[requestID] = entry
                    return requestID

            retry += 1

        raise CacheError("Failed to allocate request ID")

    def retrieve(self, requestID: int) -> CacheEntry:
        with self.cacheLock:
            return self.outstanding[requestID]

    def uncache(self, requestID: int) -> None:
        with self.cacheLock:
            try:
                del self.outstanding[requestID]
            except KeyError:
                pass

    def prepareDataElements(self,
        msg: Asn1Data,
    ) -> Tuple[Message, RequestHandle[Message]]:
        message = cast(Message, Message.decode(msg, types=pduTypes))

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
