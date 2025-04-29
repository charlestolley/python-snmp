__all__ = ["HeaderData", "MessageFlags"]

from snmp.asn1 import ASN1
from snmp.ber import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *

from snmp.security import *
from snmp.security.levels import *

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
