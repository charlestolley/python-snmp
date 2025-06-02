__all__ = [
    "HeaderData", "MessageFlags", "ScopedPDU", "SecurityName",
    "SNMPv3Message", "SNMPv3WireMessage",
]

from snmp.exception import *
from snmp.asn1 import ASN1
from snmp.ber import *
from snmp.message import ProtocolVersion
from snmp.pdu import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *

from snmp.security import *
from snmp.security.levels import *

pduTypes = {
    cls.TAG: cls for cls in (
        GetRequestPDU,
        GetNextRequestPDU,
        ResponsePDU,
        SetRequestPDU,
        GetBulkRequestPDU,
        InformRequestPDU,
        SNMPv2TrapPDU,
        ReportPDU,
    )
}

class SecurityName:
    def __init__(self, userName: bytes, *namespaces: str):
        self.userName = userName
        self.namespaces = set(namespaces)

class MessageFlags(OctetString):
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
    def construct(cls, data: Union[bytes, subbytes]) -> "MessageFlags":
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
            raise ParseError(f"Invalid msgFlags: {err}") from err

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

    @property
    def privFlag(self) -> bool:
        return self.securityLevel.priv

class HeaderData(Sequence):
    def __init__(self,
        msgID: int,
        maxSize: int,
        flags: MessageFlags,
        securityModel: SecurityModel,
    ) -> None:
        if msgID < 0:
            raise ValueError(f"Message ID may not be negative: {msgID}")

        if maxSize < 484:
            raise ValueError(f"msgMaxSize must be at least 484: {maxSize}")

        self._msgID = Integer(msgID)
        self._maxSize = Integer(maxSize)
        self.flags = flags
        self.securityModel = securityModel

    @property
    def id(self) -> int:
        return self.msgID

    @property
    def msgID(self) -> int:
        return self._msgID.value

    @property
    def maxSize(self) -> int:
        return self._maxSize.value

    def __iter__(self) -> Iterator[ASN1]:
        yield self._msgID
        yield self._maxSize
        yield self.flags
        yield Integer(self.securityModel)

    def __len__(self) -> int:
        return 4

    def __repr__(self) -> str:
        args = (
            str(self.id),
            str(self.maxSize),
            repr(self.flags),
            str(self.securityModel),
        )

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab
        securityModel = self.securityModel

        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Message ID: {self.id}",
            f"{subindent}Sender Message Size Limit: {self.maxSize}",
            f"{self.flags.toString(depth+1, tab)}",
            f"{subindent}Security Model: {securityModel.name}"
        ))

    def withMessageID(self, messageID) -> "HeaderData":
        return HeaderData(
            messageID,
            self.maxSize,
            self.flags,
            self.securityModel,
        )

    @classmethod
    def deserialize(cls, data: Union[bytes, subbytes]) -> "HeaderData":
        msgID, data         = Integer.decode(data)
        msgMaxSize, data    = Integer.decode(data)
        msgFlags, data      = MessageFlags.decode(data)
        msgSecurityModel    = Integer.decodeExact(data)

        if msgSecurityModel.value < 1:
            raise ParseError("msgSecurityModel may not be less than 1")

        try:
            securityModel = SecurityModel(msgSecurityModel.value)
        except ValueError as err:
            errmsg = f"Unknown security model: {msgSecurityModel.value}"
            raise UnknownSecurityModel(errmsg) from err

        try:
            return cls(msgID.value, msgMaxSize.value, msgFlags, securityModel)
        except ValueError as err:
            raise ParseError(*err.args) from err

class ScopedPDU(Sequence):
    def __init__(self,
        pdu: AnyPDU,
        contextEngineID: bytes,
        contextName: bytes = b"",
    ) -> None:
        self._contextEngineID = OctetString(contextEngineID)
        self._contextName = OctetString(contextName)
        self.pdu = pdu

    @property
    def contextEngineID(self) -> bytes:
        return self._contextEngineID.data

    @property
    def contextName(self) -> bytes:
        return self._contextName.data

    def __iter__(self) -> Iterator[ASN1]:
        yield self._contextEngineID
        yield self._contextName
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
    def deserialize(cls, data: Union[bytes, subbytes]) -> "ScopedPDU":
        contextEngineID, data   = OctetString.decode(data)
        contextName, data       = OctetString.decode(data)
        tag, _                  = Tag.decode(data)

        try:
            pduType = pduTypes[tag]
        except KeyError as err:
            errmsg = f"{typename(cls)} does not support PDUs of type {tag}"
            raise ParseError(errmsg) from err

        return cls(
            pduType.decodeExact(data),
            contextEngineID = contextEngineID.data,
            contextName     = contextName.data,
        )

class SNMPv3Message:
    def __init__(self,
        header: HeaderData,
        scopedPDU: ScopedPDU,
        securityEngineID: bytes,
        securityName: SecurityName,
    ) -> None:
        self.header = header
        self.scopedPDU = scopedPDU
        self.securityEngineID = securityEngineID
        self.securityName = securityName

    def __eq__(self, other: Any) -> bool:
        try:
            return (self.header == other.header
                and self.scopedPDU == other.scopedPDU
                and self.securityEngineID == other.securityEngineID
                and self.securityName == other.securityName
            )
        except AttributeError:
            return NotImplemented

    def __repr__(self) -> str:
        args = (repr(field) for field in (
            self.header,
            self.scopedPDU,
            self.securityEngineID,
            self.securityName,
        ))

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab

        return "\n".join((
            f"{indent}{typename(self)}:",
            self.header.toString(depth+1, tab),
            f"{subindent}Security EngineID: {self.securityEngineID}",
            f"{subindent}Security Name: {self.securityName.userName}",
            self.scopedPDU.toString(depth+1, tab),
        ))

    def withMessageID(self, messageID) -> "SNMPv3Message":
        return SNMPv3Message(
            self.header.withMessageID(messageID),
            self.scopedPDU,
            self.securityEngineID,
            self.securityName,
        )

class SNMPv3WireMessage(Sequence):
    VERSION = ProtocolVersion.SNMPv3

    def __init__(self,
        header: HeaderData,
        scopedPduData: Union[ScopedPDU, OctetString],
        securityParameters: OctetString,
    ) -> None:
        if header.flags.privFlag:
            if not isinstance(scopedPduData, OctetString):
                raise TypeError(
                    "scopedPduData must be an OctetString"
                    " when the privFlag is set"
                )
        else:
            if not isinstance(scopedPduData, ScopedPDU):
                raise TypeError(
                    "scopedPduData must be a ScopedPDU"
                    " when the privFlag is unset"
                )

        self.header = header
        self.scopedPduData = scopedPduData
        self.securityParameters = securityParameters

    def __iter__(self) -> Iterator[ASN1]:
        yield Integer(self.VERSION)
        yield self.header
        yield self.securityParameters
        yield self.scopedPduData

    def __len__(self) -> int:
        return 4;

    def __repr__(self) -> str:
        args = (repr(field) for field in (
            self.header,
            self.scopedPduData,
            self.securityParameters,
        ))

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab

        if self.header.flags.privFlag:
            payload = f"{subindent}Encrypted Data: {self.scopedPduData}"
        else:
            payload = self.scopedPduData.toString(depth+1, tab)

        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{self.header.toString(depth+1, tab)}",
            f"{subindent}Security Parameters: {self.securityParameters}",
            payload,
        ))

    @classmethod
    def deserialize(cls, data: Union[bytes, subbytes]) -> "SNMPv3WireMessage":
        msgVersion, ptr = Integer.decode(data)

        try:
            version = ProtocolVersion(msgVersion.value)
        except ValueError as err:
            errmsg = f"Unsupported msgVersion: {msgVersion.value}"
            raise ParseError(errmsg) from err

        if version != cls.VERSION:
            errmsg = f"{typename(cls)} cannot decode {version.name} messages"
            raise ParseError(errmsg)

        msgGlobalData, ptr = HeaderData.decode(ptr)
        msgSecurityData, ptr = OctetString.decode(ptr, copy=False)

        if msgGlobalData.flags.privFlag:
            scopedPduData = OctetString.decodeExact(ptr)
        else:
            scopedPduData = ScopedPDU.decodeExact(ptr)

        return cls(msgGlobalData, scopedPduData, msgSecurityData)

    @classmethod
    def findSecurityParameters(self, wholeMsg: bytes) -> subbytes:
        tag, ptr, tail      = decode(wholeMsg)
        tag, version, ptr   = decode(ptr)
        tag, header, ptr    = decode(ptr)
        tag, ptr, tail      = decode(ptr)
        return ptr

    @staticmethod
    def decodePlaintext(data: Union[bytes, subbytes]) -> ScopedPDU:
        scopedPDU, padding = ScopedPDU.decode(data)
        return scopedPDU
