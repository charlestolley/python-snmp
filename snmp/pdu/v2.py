__all__ = ["NoSuchObject", "NoSuchInstance", "EndOfMibView", "VarBind"]

from snmp.ber import *
from snmp.smi.v2 import *
from snmp.types import *
from snmp.utils import subbytes

class NoSuchObject(Null):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_PRIMITIVE, 0)

class NoSuchInstance(Null):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_PRIMITIVE, 1)

class EndOfMibView(Null):
    TYPE = Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_PRIMITIVE, 2)

class VarBind(Sequence):
    TYPES = {
        cls.TYPE: cls for cls in (
            Integer,
            OctetString,
            Null,
            OID,
            IpAddress,
            Counter32,
            Unsigned32,
            TimeTicks,
            Opaque,
            Counter64,
            NoSuchObject,
            NoSuchInstance,
            EndOfMibView,
        )
    }

    def __init__(self, name, value=None):
        if not isinstance(name, OID):
            name = OID(name)

        if value is None:
            value = Null()

        self.name = name
        self.value = value

    @property
    def objects(self):
        yield self.name
        yield self.value

    @classmethod
    def deserialize(cls, data):
        name, data = OID.decode(data, leftovers=True)
        identifier = decode_identifier(subbytes(data))

        try:
            valueType = cls.TYPES[identifier]
        except KeyError as err:
            msg = "Invalid variable value type: {}"
            raise ParseError(msg.format(identifier)) from err

        return cls(name, valueType.decode(data))
