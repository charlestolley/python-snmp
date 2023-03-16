__all__ = [
    "Integer32", "IpAddress", "Counter32", "Gauge32",
    "Unsigned32", "TimeTicks", "Opaque", "Counter64",
    "zeroDotZero",
]

from socket import inet_aton, inet_ntoa

from snmp.ber import *
from snmp.types import *
from snmp.typing import *
from snmp.utils import *

class Unsigned(Integer):
    SIGNED = False

@final
class Integer32(Integer):
    pass

@final
class IpAddress(OctetString):
    TYPE = Identifier(Class.APPLICATION, Structure.PRIMITIVE, 0)
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
class Counter32(Unsigned):
    TYPE = Identifier(Class.APPLICATION, Structure.PRIMITIVE, 1)

class Unsigned32(Unsigned):
    TYPE = Identifier(Class.APPLICATION, Structure.PRIMITIVE, 2)

@final
class Gauge32(Unsigned32):
    pass

@final
class TimeTicks(Unsigned):
    TYPE = Identifier(Class.APPLICATION, Structure.PRIMITIVE, 3)

@final
class Opaque(OctetString):
    TYPE = Identifier(Class.APPLICATION, Structure.PRIMITIVE, 4)

@final
class Counter64(Unsigned):
    BITS = 64
    TYPE = Identifier(Class.APPLICATION, Structure.PRIMITIVE, 6)

zeroDotZero = OID(0, 0)
