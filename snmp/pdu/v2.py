__all__ = [
    "NoSuchObject", "NoSuchInstance", "EndOfMibView",
    "VarBind", "VarBindList"
]

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

class VarBindList(Sequence):
    def __init__(self, *args):
        self.objects = [None] * len(args)
        for i, var in enumerate(args):
            if not isinstance(var, VarBind):
                var = VarBind(var)
            self.objects[i] = var

    def __iter__(self):
        return iter(self.objects)

    def __getitem__(self, key):
        return self.objects[key]

    @classmethod
    def deserialize(cls, data):
        objects = []

        while data:
            var, data = VarBind.decode(data, leftovers=True)
            objects.append(var)

        return cls(*objects)
