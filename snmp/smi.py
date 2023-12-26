__all__ = [
    "Integer", "Integer32", "Unsigned", "Unsigned32",
    "Counter32", "Gauge32", "TimeTicks", "Counter64",
    "OctetString", "IpAddress", "Opaque",
    "NULL", "Null", "OID", "zeroDotZero",
    "Sequence",
]

from socket import inet_aton, inet_ntoa

from snmp.asn1 import *
from snmp.ber import *
from snmp.typing import *
from snmp.utils import *

TPrimitive      = TypeVar("TPrimitive",     bound="Primitive")
TInteger        = TypeVar("TInteger",       bound="BoundedInteger")
TOctetString    = TypeVar("TOctetString",   bound="OctetString")

class BoundedInteger(INTEGER):
    BITS:   ClassVar[int]
    SIGNED: ClassVar[bool]

    def __init__(self, value: int) -> None:
        if not self.inRange(value):
            raise ValueError(f"{value} is out of range for {typename(self)}")

        super().__init__(value)

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

class OctetString(OCTET_STRING):
    def __init__(self, data: Asn1Data = b"") -> None:
        self.check(data)

        self._original = data
        if isinstance(data, subbytes):
            data = data[:]

        super().__init__(data)

    def __repr__(self) -> str:
        return f"{typename(self)}({self.original!r})"

    @property
    def original(self) -> Asn1Data:
        return self._original

    @classmethod
    def check(cls, data: Asn1Data) -> None:
        if len(data) > 0xffff:
            raise ValueError(f"{typename(cls)} is limited to {0xffff} bytes")

    @classmethod
    def construct(cls: Type[TOctetString], data: Asn1Data) -> TOctetString:
        try:
            return cls(data)
        except ValueError as err:
            raise ParseError(*err.args) from err

@final
class IpAddress(OCTET_STRING):
    TAG = Tag(0, cls = Tag.Class.APPLICATION)

    def __init__(self, addr: str) -> None:
        try:
            data = inet_aton(addr)
        except OSError as err:
            raise ValueError(f"Invalid IPv4 address: \"{addr}\"") from err

        super().__init__(data)
        self.addr = addr

    def __repr__(self) -> str:
        return f"{typename(self)}({repr(self.addr)})"

    def asOID(self, implied: bool = False) -> Iterable[int]:
        return super().asOID(implied=True)

    @classmethod
    def construct(cls, data: Asn1Data) -> "IpAddress":
        if isinstance(data, subbytes):
            data = data[:]

        try:
            addr = inet_ntoa(data)
        except OSError as err:
            raise ParseError(f"Invalid IPv4 address: {data!r}") from err

        return cls(addr)

@final
class Opaque(OCTET_STRING):
    TAG = Tag(4, cls = Tag.Class.APPLICATION)

Null = NULL

class OID(OBJECT_IDENTIFIER):
    def __init__(self, *subidentifiers: int) -> None:
        if len(subidentifiers) > 128:
            errmsg = "OID may not contain more than 128 sub-identifiers"
            raise ValueError(errmsg)

        if any(map(lambda x: x.bit_length() > 32, subidentifiers)):
            raise ValueError("Sub-identifiers are limited to 32-bits unsigned")

        super().__init__(*subidentifiers)

    def getIndex(self,
        prefix: "OID",
        cls: Type[TPrimitive] = Integer,    # type: ignore[assignment]
        implied: bool = False,
    ) -> TPrimitive:
        return self.decodeIndex(prefix, cls, implied=implied)[0]

zeroDotZero = OID(0, 0)

class Sequence(SEQUENCE):
    pass
