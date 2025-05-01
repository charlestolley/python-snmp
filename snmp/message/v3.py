__all__ = ["SNMPv3MessageProcessor"]

import weakref

from snmp.asn1 import *
from snmp.ber import *
from snmp.exception import *
from snmp.message import *
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *
from snmp.v3.message import *

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

class InvalidMessage(IncomingMessageError):
    pass

class LateResponse(IncomingMessageError):
    pass

class ResponseMismatch(IncomingMessageError):
    @classmethod
    def byField(cls, field: str) -> "ResponseMismatch":
        return cls(f"{field} does not match request")

class CacheEntry:
    def __init__(self,
        engineID: bytes,
        contextName: bytes,
        handle: RequestHandle[SNMPv3Message],
        securityName: bytes,
        securityModel: SecurityModel,
        securityLevel: SecurityLevel,
    ):
        self.context = contextName
        self.engineID = engineID
        self.handle = weakref.ref(handle)
        self.securityName = securityName
        self.securityModel = securityModel
        self.securityLevel = securityLevel

class SNMPv3MessageProcessor(MessageProcessor[SNMPv3Message, AnyPDU]):
    VERSION = ProtocolVersion.SNMPv3

    def __init__(self, msgMaxSize: int) -> None:
        self.msgMaxSize = msgMaxSize

        self.generator = self.newGenerator()
        self.outstanding: Dict[int, CacheEntry] = {}

        self.defaultSecurityModel: Optional[SecurityModel] = None
        self.securityModules: Dict[SecurityModel, SecurityModule[Any]] = {}

    @staticmethod
    def newGenerator() -> NumberGenerator:
        return NumberGenerator(31, signed=False)

    def cache(self, entry: CacheEntry) -> int:
        retry = 0
        while retry < 10:
            msgID = next(self.generator)
            if msgID == 0:
                self.generator = self.newGenerator()
            elif msgID not in self.outstanding:
                self.outstanding[msgID] = entry
                return msgID

            retry += 1

        raise CacheError("Failed to allocate message ID")

    def retrieve(self, msgID: int) -> CacheEntry:
        return self.outstanding[msgID]

    def uncache(self, msgID: int) -> None:
        try:
            del self.outstanding[msgID]
        except KeyError:
            pass

    def addSecurityModuleIfNeeded(self,
        module: SecurityModule[Any],
        default: bool = False,
    ) -> None:
        if module.MODEL not in self.securityModules:
            self.securityModules[module.MODEL] = module

            if default or self.defaultSecurityModel is None:
                self.defaultSecurityModel = module.MODEL

    def prepareDataElements(self,
        msg: Asn1Data,
    ) -> Tuple[SNMPv3Message, RequestHandle[SNMPv3Message]]:
        wireMessage = SNMPv3WireMessage.decodeExact(msg)

        try:
            securityModule = self.securityModules[
                wireMessage.header.securityModel
            ]
        except KeyError as e:
            securityModel = wireMessage.header.securityModel
            raise UnknownSecurityModel(securityModel) from e

        message = securityModule.processIncoming(wireMessage)

        try:
            assert message.scopedPDU is not None
        except AssertionError as err:
            errmsg = "securityModule.processIncoming() did not assign a" \
                "  value for message.scopedPDU"
            raise SNMPLibraryBug(errmsg) from err

        if isinstance(message.scopedPDU.pdu, Response):
            try:
                entry = self.retrieve(message.header.id)
            except KeyError as err:
                errmsg = f"Unknown msgID: {message.header.id}"
                raise ResponseMismatch(errmsg) from err

            handle = entry.handle()
            if handle is None:
                raise LateResponse("Handle has already been released")

            report = isinstance(message.scopedPDU.pdu, Internal)
            if (not report
            and message.header.flags.securityLevel < entry.securityLevel):
                raise ResponseMismatch.byField("Security Level")

            if not report and entry.engineID != message.securityEngineID:
                raise ResponseMismatch.byField("Security Engine ID")

            if entry.securityName != message.securityName.userName:
                raise ResponseMismatch.byField("Security Name")

            if (not report
            and entry.engineID != message.scopedPDU.contextEngineID):
                raise ResponseMismatch.byField("Context Engine ID")

            if entry.context != message.scopedPDU.contextName:
                raise ResponseMismatch.byField("Context Name")
        else:
            raise UnsupportedFeature("Received a non-response PDU type")

        return message, handle

    def prepareOutgoingMessage(self,
        pdu: AnyPDU,
        handle: RequestHandle[SNMPv3Message],
        engineID: bytes,
        securityName: bytes,
        namespace: str,
        securityLevel: SecurityLevel = noAuthNoPriv,
        securityModel: Optional[SecurityModel] = None,
        contextName: bytes = b"",
    ) -> bytes:

        if securityModel is None:
            assert self.defaultSecurityModel is not None
            securityModel = self.defaultSecurityModel

        try:
            securityModule = self.securityModules[securityModel]
        except KeyError as err:
            errmsg = f"Security Model {securityModel} has not been enabled"
            raise ValueError(errmsg) from err

        reportable = isinstance(pdu, Confirmed)

        if reportable:
            entry = CacheEntry(
                engineID,
                contextName,
                handle,
                securityName,
                securityModel,
                securityLevel)

            msgID = self.cache(entry)
            handle.addCallback(self.uncache, msgID)
        else:
            # This feature is not yet implemented
            msgID = next(self.generator)

        flags = MessageFlags(securityLevel, reportable)
        header = HeaderData(msgID, self.msgMaxSize, flags, securityModel)
        scopedPDU = ScopedPDU(pdu, engineID, contextName=contextName)
        message = SNMPv3Message(
            header,
            scopedPDU,
            engineID,
            SecurityName(securityName, namespace),
        )

        return securityModule.prepareOutgoing(message)
