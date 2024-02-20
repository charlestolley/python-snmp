__all__ = ["HeaderData", "MessageFlags", "ScopedPDU", "SNMPv3Message"]

import threading
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

    def __init__(self,
        securityLevel: SecurityLevel = noAuthNoPriv,
        reportable: bool = False,
    ) -> None:
        self.securityLevel = securityLevel
        self.reportableFlag = reportable

    def __repr__(self) -> str:
        return f"{typename(self)}({self.securityLevel}, {self.reportableFlag})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab

        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Security Level: {self.securityLevel}",
            f"{subindent}Reportable: {self.reportableFlag}",
        ))

    @classmethod
    def construct(cls, data: Asn1Data = b"") -> "MessageFlags":
        try:
            byte = data[0]
        except IndexError as err:
            raise ParseError(f"{typename(cls)} must contain at least one byte")

        try:
            securityLevel = SecurityLevel(
                byte & cls.AUTH_FLAG,
                byte & cls.PRIV_FLAG,
            )
        except ValueError as err:
            raise InvalidMessage(f"Invalid msgFlags: {err}") from err

        reportable = (byte & cls.REPORTABLE_FLAG != 0)
        return cls(securityLevel, reportable)

    @property
    def data(self) -> bytes:
        byte = 0

        if self.authFlag:
            byte |= self.AUTH_FLAG

        if self.privFlag:
            byte |= self.PRIV_FLAG

        if self.reportableFlag:
            byte |= self.REPORTABLE_FLAG

        return bytes((byte,))

    @property
    def authFlag(self) -> bool:
        return self.securityLevel.auth

    @authFlag.setter
    def authFlag(self, value: Any) -> None:
        auth = bool(value)
        if auth != self.securityLevel.auth:
            self.securityLevel = SecurityLevel(
                auth,
                self.securityLevel.priv,
            )

    @property
    def privFlag(self) -> bool:
        return self.securityLevel.priv

    @privFlag.setter
    def privFlag(self, value: Any) -> None:
        priv = bool(value)
        if priv != self.securityLevel.priv:
            self.securityLevel = SecurityLevel(
                self.securityLevel.auth,
                priv,
            )

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

    def __iter__(self) -> Iterator[ASN1]:
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
            f"{self.flags.toString(depth+1, tab)}",
            f"{subindent}Security Model: {securityModel.name}"
        ))

    @classmethod
    def deserialize(cls, data: Asn1Data) -> "HeaderData":
        msgID, data = cast(
            Tuple[Integer, subbytes],
            Integer.decode(data, leftovers=True),
        )

        msgMaxSize, data = cast(
            Tuple[Integer, subbytes],
            Integer.decode(data, leftovers=True),
        )

        msgFlags, data = cast(
            Tuple[MessageFlags, subbytes],
            MessageFlags.decode(data, leftovers=True),
        )

        msgSecurityModel = Integer.decode(data)

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

    def __iter__(self) -> Iterator[ASN1]:
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
        types: Optional[Mapping[Tag, Type[AnyPDU]]] = None,
    ) -> "ScopedPDU":
        if types is None:
            types = dict()

        contextEngineID, data = cast(
            Tuple[OctetString, subbytes],
            OctetString.decode(data, leftovers=True),
        )

        contextName, data = cast(
            Tuple[OctetString, subbytes],
            OctetString.decode(data, leftovers=True),
        )

        identifier, _ = Tag.decode(subbytes(data))

        try:
            pduType = types[identifier]
        except KeyError as err:
            raise ParseError(f"Invalid PDU type: {identifier}") from err

        return cls(
            cast(AnyPDU, pduType.decode(data)),
            contextEngineID = contextEngineID.data,
            contextName     = contextName.data,
        )

TMessage = TypeVar("TMessage", bound="SNMPv3Message")
class SNMPv3Message(Sequence):
    VERSION = MessageProcessingModel.SNMPv3

    def __init__(self,
        header: HeaderData,
        scopedPDU: Optional[ScopedPDU] = None,
        encryptedPDU: Optional[OctetString] = None,
        securityParameters: Optional[OctetString] = None,
        securityEngineID: Optional[bytes] = None,
        securityName: Optional[bytes] = None,
    ) -> None:
        self.header = header
        self.scopedPDU = scopedPDU
        self.encryptedPDU = encryptedPDU

        if securityParameters is None:
            securityParameters = OctetString()

        self.securityParameters = securityParameters
        self.securityEngineID = securityEngineID
        self.securityName = securityName

    def __iter__(self) -> Iterator[ASN1]:
        yield Integer(self.VERSION)
        yield self.header
        yield self.securityParameters

        if self.header.flags.privFlag:
            assert self.encryptedPDU is not None
            yield self.encryptedPDU
        else:
            assert self.scopedPDU is not None
            yield self.scopedPDU

    def __len__(self) -> int:
        return 4;

    def __repr__(self) -> str:
        args = [repr(self.header)]

        if self.header.flags.privFlag:
            args.append(f"encryptedPDU={repr(self.encryptedPDU)}")
        else:
            args.append(f"scopedPDU={repr(self.scopedPDU)}")

        args.append(f"securityParameters={repr(self.securityParameters)}")

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab

        if self.header.flags.privFlag:
            payload = f"{subindent}Encrypted Data: {self.encryptedPDU}"
        else:
            assert self.scopedPDU is not None
            payload = self.scopedPDU.toString(depth+1, tab)

        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{self.header.toString(depth+1, tab)}",
            f"{subindent}Security Parameters: {self.securityParameters}",
            payload,
        ))

    @overload
    @classmethod
    def decode(
        cls: Type[TMessage],
        data: Asn1Data,
    ) -> TMessage:
        ...

    @overload
    @classmethod
    def decode(
        cls: Type[TMessage],
        data: Asn1Data,
        leftovers: bool = False,
        copy: bool = True,
        **kwargs: Any,
    ) -> Union[TMessage, Tuple[TMessage, subbytes]]:
        ...

    @classmethod
    def decode(cls: Type[TMessage],
        data: Asn1Data,
        leftovers: bool = False,
        copy: bool = False,
        **kwargs: Any,
    ) -> Union[TMessage, Tuple[TMessage, subbytes]]:
        return super().decode(data, leftovers, copy, **kwargs)

    @classmethod
    def deserialize(cls: Type[TMessage], data: Asn1Data) -> TMessage:
        msgVersion, ptr = cast(
            Tuple[Integer, subbytes],
            Integer.decode(data, leftovers=True),
        )

        try:
            version = MessageProcessingModel(msgVersion.value)
        except ValueError as err:
            raise BadVersion(msgVersion.value) from err

        if version != cls.VERSION:
            raise BadVersion(f"{typename} does not support {version.name}")

        msgGlobalData, ptr = cast(
            Tuple[HeaderData, subbytes],
            HeaderData.decode(ptr, leftovers=True),
        )

        msgSecurityData, ptr = cast(
            Tuple[OctetString, subbytes],
            OctetString.decode(ptr, leftovers=True, copy=False),
        )

        scopedPDU = None
        encryptedPDU = None
        if msgGlobalData.flags.privFlag:
            encryptedPDU = OctetString.decode(ptr)
        else:
            scopedPDU = cast(ScopedPDU, ScopedPDU.decode(ptr, types=pduTypes))

        return cls(
            msgGlobalData,
            scopedPDU=scopedPDU,
            encryptedPDU=encryptedPDU,
            securityParameters=msgSecurityData,
        )

    @classmethod
    def findSecurityParameters(self, wholeMsg: bytes) -> subbytes:
        ptr: subbytes = decode(wholeMsg, self.TAG, copy=False)

        _, ptr = decode(ptr, Integer.TAG,       leftovers=True, copy=False)
        _, ptr = decode(ptr, Sequence.TAG,      leftovers=True, copy=False)
        ptr, _ = decode(ptr, OctetString.TAG,   leftovers=True, copy=False)

        return ptr

    @property
    def plaintext(self) -> bytes:
        assert self.scopedPDU is not None
        return self.scopedPDU.encode()

    @plaintext.setter
    def plaintext(self, data: bytes) -> None:
        self.scopedPDU, _ = cast(
            Tuple[ScopedPDU, subbytes],
            ScopedPDU.decode(data, leftovers=True, types=pduTypes),
        )

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
    VERSION = MessageProcessingModel.SNMPv3

    def __init__(self, msgMaxSize: int) -> None:
        self.msgMaxSize = msgMaxSize

        self.cacheLock = threading.Lock()
        self.generator = self.newGenerator()
        self.outstanding: Dict[int, CacheEntry] = {}

        self.securityLock = threading.Lock()
        self.defaultSecurityModel: Optional[SecurityModel] = None
        self.securityModules: Dict[SecurityModel, SecurityModule[Any]] = {}

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
        module: SecurityModule[Any],
        default: bool = False,
    ) -> None:
        with self.securityLock:
            if module.MODEL not in self.securityModules:
                self.securityModules[module.MODEL] = module

                if default or self.defaultSecurityModel is None:
                    self.defaultSecurityModel = module.MODEL

    def prepareDataElements(self,
        msg: Asn1Data,
    ) -> Tuple[SNMPv3Message, RequestHandle[SNMPv3Message]]:
        message = SNMPv3Message.decode(msg)

        with self.securityLock:
            try:
                securityModule = self.securityModules[
                    message.header.securityModel
                ]
            except KeyError as e:
                securityModel = message.header.securityModel
                raise UnknownSecurityModel(securityModel) from e

        securityModule.processIncoming(message)
        assert message.scopedPDU is not None

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

            if entry.securityName != message.securityName:
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

        flags = MessageFlags(securityLevel, isinstance(pdu, Confirmed))
        header = HeaderData(msgID, self.msgMaxSize, flags, securityModel)
        scopedPDU = ScopedPDU(pdu, engineID, contextName=contextName)
        message = SNMPv3Message(header, scopedPDU)

        return securityModule.prepareOutgoing(message, engineID, securityName)
