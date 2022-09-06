import threading
import weakref

from snmp.ber import *
from snmp.ber import ParseError, decode_identifier
from snmp.exception import *
from snmp.message import *
from snmp.pdu import *
from snmp.types import *
from snmp.utils import *
from . import *

pduTypes = {
    cls.TYPE: cls for cls in (
        GetRequestPDU,
        GetNextRequestPDU,
        ResponsePDU,
        SetRequestPDU,
        TrapPDU,
    )
}

class LateResponse(IncomingMessageError):
    pass

class ResponseMismatch(IncomingMessageError):
    @classmethod
    def byField(cls, field):
        return cls(f"{field} does not match request")

class CacheEntry:
    def __init__(self, handle, community):
        self.community = community
        self.handle = weakref.ref(handle)

class MessageProcessor:
    VERSION = MessageProcessingModel.SNMPv1

    def __init__(self):
        self.cacheLock = threading.Lock()
        self.generator = self.newGenerator()
        self.outstanding = {}

    @staticmethod
    def newGenerator():
        return NumberGenerator(32)

    def cache(self, entry, credentials=None):
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

        raise Exception("Failed to allocate request ID")

    def retrieve(self, requestID):
        with self.cacheLock:
            return self.outstanding[requestID]

    def uncache(self, requestID):
        with self.cacheLock:
            try:
                del self.outstanding[requestID]
            except KeyError:
                pass

    def prepareDataElements(self, msg):
        community, msg = OctetString.decode(msg, leftovers=True)
        identifier = decode_identifier(subbytes(msg))

        try:
            pduType = pduTypes[identifier]
        except KeyError as err:
            raise ParseError(f"Invalid PDU type: {identifier}") from err

        pdu = pduType.decode(msg)
        if isinstance(pdu, ResponsePDU):
            try:
                entry = self.retrieve(pdu.requestID)
            except KeyError as err:
                errmsg = f"Unknown requestID: {pdu.requestID}"
                raise ResponseMismatch(errmsg) from err

            handle = entry.handle()
            if handle is None:
                raise LateResponse("Handle has already been released")

            if entry.community != community.data:
                raise ResponseMismatch.byField("Community")
        else:
            raise UnsupportedFeature("Received a non-response PDU type")

        return Message(self.VERSION, community, pdu), handle

    def prepareOutgoingMessage(self, pdu, handle, community):
        if pdu.requestID == 0:
            cacheEntry = CacheEntry(handle, community)
            pdu.requestID = self.cache(cacheEntry)
            handle.addCallback(self.uncache, pdu.requestID)

        return Message(self.VERSION, community, pdu).encode()
