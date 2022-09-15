__all__ = [
    "Integer32", "IpAddress", "Counter32", "Gauge32",
    "Unsigned32", "TimeTicks", "Opaque", "Counter64",
    "zeroDotZero",
]

from socket import inet_aton, inet_ntoa
from snmp.ber import *
from snmp.types import *
from snmp.utils import *

class Unsigned(Integer):
    SIGNED = False

class Integer32(Integer):
    pass

class IpAddress(OctetString):
    TYPE = Identifier(CLASS_APPLICATION, STRUCTURE_PRIMITIVE, 0)
    MIN_SIZE = 4
    MAX_SIZE = 4

    def __init__(self, addr):
        self.addr = addr

    def __repr__(self):
        return f"{typename(self)}({repr(self.addr)})"

    def equals(self, other):
        return self.data == other.data

    @property
    def data(self):
        try:
            return inet_aton(self.addr)
        except OSError as err:
            raise ValueError(f"Invalid IPv4 address: \"{self.addr}\"") from err

    @classmethod
    def parse(cls, data):
        addr = data[:] if isinstance(data, subbytes) else data
        return cls(inet_ntoa(addr))

class Counter32(Unsigned):
    TYPE = Identifier(CLASS_APPLICATION, STRUCTURE_PRIMITIVE, 1)

class Unsigned32(Unsigned):
    TYPE = Identifier(CLASS_APPLICATION, STRUCTURE_PRIMITIVE, 2)

Gauge32 = Unsigned32

class TimeTicks(Unsigned):
    TYPE = Identifier(CLASS_APPLICATION, STRUCTURE_PRIMITIVE, 3)

class Opaque(OctetString):
    TYPE = Identifier(CLASS_APPLICATION, STRUCTURE_PRIMITIVE, 4)

class Counter64(Unsigned):
    BITS = 64
    TYPE = Identifier(CLASS_APPLICATION, STRUCTURE_PRIMITIVE, 6)

zeroDotZero = OID(0, 0)
