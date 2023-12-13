__all__ = [
    "Integer", "Integer32", "Unsigned", "Unsigned32",
    "Counter32", "Gauge32", "TimeTicks", "Counter64",
    "IpAddress", "Opaque", "zeroDotZero",
]

from socket import inet_aton, inet_ntoa

from snmp.ber import *
from snmp.types import *
from snmp.asn1 import *
from snmp.typing import *
from snmp.utils import *

TInteger = TypeVar("TInteger", bound="BoundedInteger")

class BoundedInteger(INTEGER):
    BITS:   ClassVar[int]
    SIGNED: ClassVar[bool]

    def __init__(self, value: int) -> None:
        if not self.inRange(value):
            raise ValueError(f"{value} is out of range for {typename(self)}")

        super().__init__(value)

    def __eq__(self, other: Any) -> bool:
        equal = super().__eq__(other)

        if isinstance(equal, bool):
            return equal and self.TAG == other.TAG
        else:
            return equal

    @classmethod
    def construct(cls: Type[TInteger], value: int) -> TInteger:
        try:
            return cls(value)
        except ValueError as err:
            raise ParseError(*err.args)

    @classmethod
    def inRange(cls, value: int) -> bool:
        if value < 0 and not cls.SIGNED:
            return False

        nbits = cls.bitCount(value)
        allowable = cls.BITS - 1 if cls.SIGNED else cls.BITS
        return nbits <= allowable

class Integer32(BoundedInteger):
    BITS = 32
    SIGNED  = True

class Unsigned32(BoundedInteger):
    BITS = 32
    SIGNED = False
    TAG = Tag(2, cls = Tag.Class.APPLICATION)

Integer = Integer32
Unsigned = Unsigned32

@final
class Counter32(Unsigned32):
    TAG = Tag(1, cls = Tag.Class.APPLICATION)

@final
class Gauge32(Unsigned32):
    pass

@final
class TimeTicks(Unsigned32):
    TAG = Tag(3, cls = Tag.Class.APPLICATION)

@final
class Counter64(BoundedInteger):
    BITS = 64
    SIGNED = False
    TAG = Tag(6, cls = Tag.Class.APPLICATION)

@final
class IpAddress(OctetString):
    TAG = Tag(0, cls = Tag.Class.APPLICATION)
    MIN_SIZE = 4
    MAX_SIZE = 4

    def __init__(self, addr: str) -> None:
        self.addr = addr

    def __repr__(self) -> str:
        return f"{typename(self)}({repr(self.addr)})"

    def equals(self, other: OctetString) -> bool:
        return self.data == other.data

    @property
    def data(self) -> bytes:
        try:
            return inet_aton(self.addr)
        except OSError as err:
            raise ValueError(f"Invalid IPv4 address: \"{self.addr}\"") from err

    @classmethod
    def interpret(cls, data: Asn1Data) -> "IpAddress":
        addr = data[:] if isinstance(data, subbytes) else data
        return cls(inet_ntoa(addr))

@final
class Opaque(OctetString):
    TAG = Tag(4, cls = Tag.Class.APPLICATION)

zeroDotZero = OID(0, 0)
