import threading
import weakref

from snmp.ber import *
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
        GetBulkRequestPDU,
        InformRequestPDU,
        SNMPv2TrapPDU,
        ReportPDU,
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
        self.community = community if isinstance (community, bytes) else bytes (community, "latin_1")
        self.handle = weakref.ref(handle)

class MessageProcessor:
    VERSION = MessageProcessingModel.SNMPv2c

    def __init__(self):
        self.cacheLock = threading.Lock()
        self.generator = self.newGenerator()
        self.outstanding = {}

    @staticmethod
    def newGenerator():
        return NumberGenerator(32)

    def cache(self, entry):
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
        message = Message.decodeBody(msg, pduTypes)

        if isinstance(message.pdu, ResponsePDU):
            try:
                entry = self.retrieve(message.pdu.requestID)
            except KeyError as err:
                errmsg = f"Unknown requestID: {message.pdu.requestID}"
                raise ResponseMismatch(errmsg) from err

            handle = entry.handle()
            if handle is None:
                raise LateResponse("Handle has already been released")

            if entry.community != message.community:
                raise ResponseMismatch.byField("Community")
        else:
            raise UnsupportedFeature("Received a non-response PDU type")

        return message, handle

    def prepareOutgoingMessage(self, pdu, handle, community):
        if pdu.requestID == 0:
            cacheEntry = CacheEntry(handle, community)
            pdu.requestID = self.cache(cacheEntry)
            handle.addCallback(self.uncache, pdu.requestID)

        return Message(self.VERSION, community, pdu).encode()
