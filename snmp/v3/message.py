__all__ = ["MessageFlags"]

from snmp.ber import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *

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
