__all__ = [
    "Integer", "Integer32", "Unsigned", "Unsigned32",
    "Counter32", "Gauge32", "TimeTicks", "Counter64",
    "OctetString", "IpAddress", "Opaque",
    "NULL", "Null", "OID", "zeroDotZero",
    "Sequence", "VarBind", "VarBindList",
    "NoSuchObject", "NoSuchInstance", "EndOfMibView",
]

from socket import inet_aton, inet_ntoa

from snmp.asn1 import *
from snmp.ber import *
from snmp.utils import *

class BoundedInteger(INTEGER):
    def __init__(self, value):
        if not self.inRange(value):
            raise ValueError(f"{value} is out of range for {typename(self)}")

        super().__init__(value)

    @classmethod
    def construct(cls, value):
        try:
            return cls(value)
        except ValueError as err:
            raise cls.DeserializeError(err.args[0])

    @classmethod
    def deserialize(cls, data):
        value = int.from_bytes(data, cls.BYTEORDER, signed=cls.SIGNED)
        return cls.construct(value)

    @classmethod
    def inRange(cls, value):
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

class Counter32(Unsigned32):
    TAG = Tag(1, cls = Tag.Class.APPLICATION)

class Gauge32(Unsigned32):
    pass

class TimeTicks(Unsigned32):
    TAG = Tag(3, cls = Tag.Class.APPLICATION)

class Counter64(BoundedInteger):
    BITS = 64
    SIGNED = False
    TAG = Tag(6, cls = Tag.Class.APPLICATION)

class OctetString(OCTET_STRING):
    def __init__(self, data = b""):
        self.check(data)

        self._original = data
        super().__init__(data[:])

    def __repr__(self):
        return f"{typename(self)}({self.original!r})"

    @property
    def original(self):
        return self._original

    @classmethod
    def check(cls, data):
        if len(data) > 0xffff:
            raise ValueError(f"{typename(cls)} is limited to {0xffff} bytes")

    @classmethod
    def construct(cls, data):
        try:
            return cls(data)
        except ValueError as err:
            raise cls.DeserializeError(err.args[0]) from err

class IpAddress(OCTET_STRING):
    TAG = Tag(0, cls = Tag.Class.APPLICATION)

    def __init__(self, addr):
        try:
            data = inet_aton(addr)
        except OSError as err:
            raise ValueError(f"Invalid IPv4 address: \"{addr}\"") from err

        super().__init__(data)
        self.addr = addr

    def __repr__(self):
        return f"{typename(self)}({repr(self.addr)})"

    def asOID(self, implied = False):
        return super().asOID(implied=True)

    @classmethod
    def fromBytes(cls, data):
        try:
            addr = inet_ntoa(data)
        except OSError as err:
            errmsg = f"Invalid IPv4 address encoding: {data!r}"
            raise ValueError(errmsg) from err

        return cls(addr)

    @classmethod
    def fromOID(cls, nums, implied = False):
        data = bytes(next(nums) for i in range(4))
        return cls.fromBytes(data)

    @classmethod
    def construct(cls, data):
        try:
            return cls.fromBytes(data[:])
        except ValueError as err:
            raise cls.DeserializeError(err.args[0]) from err

class Opaque(OCTET_STRING):
    TAG = Tag(4, cls = Tag.Class.APPLICATION)

Null = NULL

class NoSuchObject(Null):
    TAG = Tag(0, cls = Tag.Class.CONTEXT_SPECIFIC)

class NoSuchInstance(Null):
    TAG = Tag(1, cls = Tag.Class.CONTEXT_SPECIFIC)

class EndOfMibView(Null):
    TAG = Tag(2, cls = Tag.Class.CONTEXT_SPECIFIC)

class OID(OBJECT_IDENTIFIER):
    def __init__(self, *subidentifiers):
        if len(subidentifiers) > 128:
            errmsg = "OID may not contain more than 128 sub-identifiers"
            raise ValueError(errmsg)

        if any(map(lambda x: x.bit_length() > 32, subidentifiers)):
            raise ValueError("Sub-identifiers are limited to 32-bits unsigned")

        super().__init__(*subidentifiers)

    def getIndex(self, prefix, cls = Integer, implied = False):
        return self.decodeIndex(prefix, cls, implied=implied)[0]

zeroDotZero = OID(0, 0)

class Sequence(SEQUENCE):
    pass

class VarBind(Sequence):
    TYPES = {
        cls.TAG: cls for cls in (
            Integer,
            OctetString,
            Null,
            OID,
            IpAddress,
            Counter32,
            Gauge32,
            TimeTicks,
            Opaque,
            Counter64,
            NoSuchObject,
            NoSuchInstance,
            EndOfMibView,
        )
    }

    def __init__(self, name, value = None):
        if not isinstance(name, OID):
            name = OID.parse(name)

        if value is None:
            value = Null()

        self.name = name
        self.value = value

    def __iter__(self):
        yield self.name
        yield self.value

    def __len__(self):
        return 2

    def __repr__(self):
        return f"{typename(self)}({self.name!r}, {self.value!r})"

    def __str__(self):
        return f"{self.name}: {self.value}"

    @classmethod
    def deserialize(cls, data):
        name, data = OID.decode(data)
        tag, _ = Tag.decode(data)

        try:
            valueType = cls.TYPES[tag]
        except KeyError as err:
            errmsg = f"Invalid variable value type: {tag}"
            raise ParseError(errmsg, data) from err

        return cls(name, valueType.decodeExact(data))

class VarBindList(Sequence):
    def __init__(self, *args, unpack=False):
        self.variables = tuple(
            vb if isinstance(vb, VarBind) else
            VarBind(*vb) if unpack else VarBind(vb)
            for vb in args
        )

    def __bool__(self):
        return bool(self.variables)

    def __getitem__(self, key):
        return self.variables[key]

    def __iter__(self):
        return iter(self.variables)

    def __len__(self):
        return len(self.variables)

    def __repr__(self):
        args = ", ".join(repr(var) for var in self.variables)
        return f"{typename(self)}({args})"

    def __str__(self):
        return self.toString()

    def toString(self, indent = ""):
        return "\n".join(f"{indent}{var}" for var in self.variables)

    @classmethod
    def deserialize(cls, data):
        objects = []

        while data:
            var, data = VarBind.decode(data)
            objects.append(var)

        return cls(*objects)
