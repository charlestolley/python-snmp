import threading
import weakref

from snmp.ber import *
from snmp.exception import *
from snmp.message import *
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import *
from snmp.types import *
from snmp.typing import *
from snmp.utils import *

pduTypes = {
    cls.TYPE: cls for cls in cast(Tuple[Type[AnyPDU], ...], (
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

class InvalidMessage(IncomingMessageError):
    pass

class LateResponse(IncomingMessageError):
    pass

class ResponseMismatch(IncomingMessageError):
    @classmethod
    def byField(cls, field: str) -> "ResponseMismatch":
        return cls(f"{field} does not match request")

class UnknownSecurityModel(IncomingMessageError):
    pass

@final
class MessageFlags(OctetString):
    MIN_SIZE = 1

    AUTH_FLAG: ClassVar[int]        = (1 << 0)
    PRIV_FLAG: ClassVar[int]        = (1 << 1)
    REPORTABLE_FLAG: ClassVar[int]  = (1 << 2)
    ALL_FLAGS: ClassVar[int]        = AUTH_FLAG | PRIV_FLAG | REPORTABLE_FLAG

    def __init__(self, byte: int = 0) -> None:
        self.byte = byte & self.ALL_FLAGS

    def __repr__(self) -> str:
        return f"{typename(self)}({self.byte})"

    def __str__(self) -> str:
        flags = []
        if self.authFlag:
            flags.append("AUTH")

        if self.privFlag:
            flags.append("PRIV")

        if self.reportableFlag:
            flags.append("REPORTABLE")

        return f"<{','.join(flags)}>"

    @classmethod
    def interpret(cls, data: Asn1Data = b"") -> "MessageFlags":
        return cls(byte=data[0])

    @property
    def data(self) -> bytes:
        return bytes((self.byte,))

    @property
    def authFlag(self) -> bool:
        return bool(self.byte & self.AUTH_FLAG)

    @authFlag.setter
    def authFlag(self, value: Any) -> None:
        if value:
            self.byte |= self.AUTH_FLAG
        else:
            self.byte &= ~self.AUTH_FLAG

    @property
    def privFlag(self) -> bool:
        return bool(self.byte & self.PRIV_FLAG)

    @privFlag.setter
    def privFlag(self, value: Any) -> None:
        if value:
            self.byte |= self.PRIV_FLAG
        else:
            self.byte &= ~self.PRIV_FLAG

    @property
    def reportableFlag(self) -> bool:
        return bool(self.byte & self.REPORTABLE_FLAG)

    @reportableFlag.setter
    def reportableFlag(self, value: Any) -> None:
        if value:
            self.byte |= self.REPORTABLE_FLAG
        else:
            self.byte &= ~self.REPORTABLE_FLAG

@final
class HeaderData(Sequence):
    def __init__(self,
        msgID: int,
        maxSize: int,
        flags: MessageFlags,
        securityModel: SecurityModel,
    ) -> None:
        self.id = msgID
        self.maxSize = maxSize
        self.flags = flags
        self.securityModel = securityModel

    def __iter__(self) -> Iterator[Asn1Encodable]:
        yield Integer(self.id)
        yield Integer(self.maxSize)
        yield self.flags
        yield Integer(self.securityModel)

    def __len__(self) -> int:
        return 4

    def __repr__(self) -> str:
        args = (
            str(self.id),
            str(self.maxSize),
            repr(self.flags),
            str(SecurityModel(self.securityModel)),
        )

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab
        securityModel = SecurityModel(self.securityModel)
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Message ID: {self.id}",
            f"{subindent}Sender Message Size Limit: {self.maxSize}",
            f"{subindent}Flags: {self.flags}",
            f"{subindent}Security Model: {securityModel.name}"
        ))

    @classmethod
    def deserialize(cls, data: Asn1Data) -> "HeaderData":
        msgID,      data = Integer      .decode(data, leftovers=True)
        msgMaxSize, data = Integer      .decode(data, leftovers=True)
        msgFlags,   data = MessageFlags .decode(data, leftovers=True)
        msgSecurityModel = Integer      .decode(data)

        if msgID.value < 0:
            raise ParseError("msgID may not be less than 0")
        elif msgMaxSize.value < 484:
            raise ParseError("msgMaxSize may not be less than 484")
        elif msgSecurityModel.value < 1:
            raise ParseError("msgSecurityModel may not be less than 1")

        try:
            securityModel = SecurityModel(msgSecurityModel.value)
        except ValueError as err:
            raise UnknownSecurityModel(msgSecurityModel.value) from err

        return cls(
            msgID.value,
            msgMaxSize.value,
            msgFlags,
            securityModel,
        )

@final
class ScopedPDU(Sequence):
    def __init__(self,
        pdu: AnyPDU,
        contextEngineID: bytes,
        contextName: bytes = b"",
    ) -> None:
        self.contextEngineID = contextEngineID
        self.contextName = contextName
        self.pdu = pdu

    def __iter__(self) -> Iterator[Asn1Encodable]:
        yield OctetString(self.contextEngineID)
        yield OctetString(self.contextName)
        yield self.pdu

    def __len__(self) -> int:
        return 3

    def __repr__(self) -> str:
        args = (
            repr(self.pdu),
            repr(self.contextEngineID),
            f"contextName={repr(self.contextName)}"
        )

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Context Engine ID: {self.contextEngineID!r}",
            f"{subindent}Context Name: {self.contextName!r}",
            f"{self.pdu.toString(depth=depth+1, tab=tab)}"
        ))

    @classmethod
    def deserialize(cls,
        data: Asn1Data,
        types: Optional[Mapping[Identifier, Type[AnyPDU]]] = None,
    ) -> "ScopedPDU":
        if types is None:
            types = dict()

        contextEngineID, data = OctetString.decode(data, leftovers=True)
        contextName,     data = OctetString.decode(data, leftovers=True)
        identifier = decode_identifier(subbytes(data))

        try:
            pduType = types[identifier]
        except KeyError as err:
            raise ParseError(f"Invalid PDU type: {identifier}") from err

        return cls(
            pduType.decode(data),
            contextEngineID = cast(bytes, contextEngineID.data),
            contextName     = cast(bytes, contextName.data),
        )

class SNMPv3Message:
    def __init__(self,
        msgID: int,
        securityLevel: SecurityLevel,
        securityParameters: SecurityParameters,
        data: ScopedPDU,
    ):
        self.id = msgID
        self.securityLevel = securityLevel
        self.securityEngineID = securityParameters.securityEngineID
        self.securityName = securityParameters.securityName
        self.data = data

    def __repr__(self) -> str:
        args = (repr(member) for member in (
            self.id,
            self.securityLevel,
            SecurityParameters(self.securityEngineID, self.securityName),
            self.data,
        ))

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Message ID: {self.id}",
            f"{subindent}Security Engine ID: {self.securityEngineID!r}",
            f"{subindent}Security Level: {self.securityLevel}",
            f"{subindent}Security Name: {self.securityName!r}",
            f"{self.data.toString(depth+1, tab)}",
        ))

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

class MessageProcessor:
    VERSION = MessageProcessingModel.SNMPv3

    def __init__(self) -> None:
        self.cacheLock = threading.Lock()
        self.generator = self.newGenerator()
        self.outstanding: Dict[int, CacheEntry] = {}

        self.securityLock = threading.Lock()
        self.defaultSecurityModel: Optional[SecurityModel] = None
        self.securityModules: Dict[SecurityModel, SecurityModule] = {}

    @staticmethod
    def newGenerator() -> NumberGenerator:
        return NumberGenerator(31, signed=False)

    def cache(self, entry: CacheEntry) -> int:
        retry = 0
        while retry < 10:
            with self.cacheLock:
                msgID = next(self.generator)
                if msgID == 0:
                    self.generator = self.newGenerator()
                elif msgID not in self.outstanding:
                    self.outstanding[msgID] = entry
                    return msgID

            retry += 1

        raise Exception("Failed to allocate message ID")

    def retrieve(self, msgID: int) -> CacheEntry:
        with self.cacheLock:
            return self.outstanding[msgID]

    def uncache(self, msgID: int) -> None:
        with self.cacheLock:
            try:
                del self.outstanding[msgID]
            except KeyError:
                pass

    def addSecurityModuleIfNeeded(self,
        module: SecurityModule,
        default: bool = False,
    ) -> None:
        with self.securityLock:
            if module.MODEL not in self.securityModules:
                self.securityModules[module.MODEL] = module

                if default or self.defaultSecurityModel is None:
                    self.defaultSecurityModel = module.MODEL

    def prepareDataElements(self,
        msg: subbytes,
    ) -> Tuple[SNMPv3Message, RequestHandle[SNMPv3Message]]:
        msgGlobalData, msg = HeaderData.decode(msg, leftovers=True)

        with self.securityLock:
            try:
                securityModule = self.securityModules[
                    msgGlobalData.securityModel
                ]
            except KeyError as e:
                raise UnknownSecurityModel(msgGlobalData.securityModel) from e

        try:
            securityLevel = SecurityLevel(
                auth=msgGlobalData.flags.authFlag,
                priv=msgGlobalData.flags.privFlag)
        except ValueError as err:
            raise InvalidMessage(f"Invalid msgFlags: {err}") from err

        security, data = securityModule.processIncoming(msg, securityLevel)
        scopedPDU, _ = ScopedPDU.decode(data, types=pduTypes, leftovers=True)

        if isinstance(scopedPDU.pdu, Response):
            try:
                entry = self.retrieve(msgGlobalData.id)
            except KeyError as err:
                errmsg = f"Unknown msgID: {msgGlobalData.id}"
                raise ResponseMismatch(errmsg) from err

            handle = entry.handle()
            if handle is None:
                raise LateResponse("Handle has already been released")

            report = isinstance(scopedPDU.pdu, Internal)
            if not report and entry.securityLevel < securityLevel:
                raise ResponseMismatch.byField("Security Level")

            if not report and entry.engineID != security.securityEngineID:
                raise ResponseMismatch.byField("Security Engine ID")

            if entry.securityName != security.securityName:
                raise ResponseMismatch.byField("Security Name")

            if not report and entry.engineID != scopedPDU.contextEngineID:
                raise ResponseMismatch.byField("Context Engine ID")

            if entry.context != scopedPDU.contextName:
                raise ResponseMismatch.byField("Context Name")
        else:
            raise UnsupportedFeature("Received a non-response PDU type")

        message = \
            SNMPv3Message(msgGlobalData.id, securityLevel, security, scopedPDU)
        return message, handle

    def prepareOutgoingMessage(self,
        pdu: AnyPDU,
        handle: RequestHandle[SNMPv3Message],
        engineID: bytes,
        securityName: bytes,
        securityLevel: SecurityLevel = noAuthNoPriv,
        securityModel: Optional[SecurityModel] = None,
        contextName: bytes = b"",
    ) -> bytes:

        with self.securityLock:
            if securityModel is None:
                assert self.defaultSecurityModel is not None
                securityModel = self.defaultSecurityModel

            try:
                securityModule = self.securityModules[securityModel]
            except KeyError as err:
                errmsg = f"Security Model {securityModel} has not been enabled"
                raise ValueError(errmsg) from err

        entry = CacheEntry(
            engineID,
            contextName,
            handle,
            securityName,
            securityModel,
            securityLevel)

        msgID = self.cache(entry)
        handle.addCallback(self.uncache, msgID)

        flags = MessageFlags()
        flags.authFlag = securityLevel.auth
        flags.privFlag = securityLevel.priv
        flags.reportableFlag = isinstance(pdu, Confirmed)

        msgGlobalData = HeaderData(msgID, 1472, flags, securityModel)
        header = Integer(self.VERSION).encode() + msgGlobalData.encode()
        scopedPDU = ScopedPDU(pdu, engineID, contextName=contextName)

        return securityModule.prepareOutgoing(
            header,
            scopedPDU.encode(),
            engineID,
            securityName,
            securityLevel,
        )
