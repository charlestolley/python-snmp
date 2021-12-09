__all__ = [
    "INTEGER", "OCTET_STRING", "NULL", "OBJECT_IDENTIFIER", "SEQUENCE",
    "Object", "Integer", "OctetString",
]

from snmp.ber import *

INTEGER             = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 2)
OCTET_STRING        = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 4)
NULL                = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 5)
OBJECT_IDENTIFIER   = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 6)
SEQUENCE            = Identifier(CLASS_UNIVERSAL, STRUCTURE_CONSTRUCTED, 16)

class Object:
    @classmethod
    def decode(cls, data, leftovers=False, **kwargs):
        result = decode(
            data,
            expected=cls.TYPE,
            leftovers=leftovers)

        if leftovers:
            encoding, leftovers = result
            return cls.deserialize(encoding, **kwargs), leftovers
        else:
            return cls.deserialize(result, **kwargs)

    def encode(self):
        return encode(self.TYPE, self.serialize())

    @classmethod
    def deserialize(cls, data):
        raise AttributeError(
            "{} does not override deserialize()".format(cls.__name__)
        )

    def serialize(self):
        raise AttributeError(
            "{} does not override serialize()".format(self.__class__.__name__)
        )

class Primitive(Object):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "{}: {}".format(self.__class__.__name__, self.value)

class Integer(Primitive):
    SIGNED = True
    SIZE = 4
    TYPE = INTEGER

    @classmethod
    def deserialize(cls, data):
        for i in range(len(data) - cls.SIZE):
            if data[i] != 0:
                msg = "Encoding too large for {}".format(cls.__name__)
                raise ParseError(msg)

        return int.from_bytes(data, "big", signed=cls.SIGNED)

    def serialize(self):
        encoding = self.value.to_bytes(self.SIZE, "big", signed=self.SIGNED)

        if encoding[0]:
            return encoding

        for index in range(1, len(encoding)):
            if encoding[index]:
                if self.SIGNED and encoding[index] & 0x80:
                    index -= 1
                break

        return encoding[index:]

class OctetString(Primitive):
    TYPE = OCTET_STRING

    @classmethod
    def deserialize(cls, data, copy=True):
        if copy:
            return bytes(data)
        else:
            return data

    def serialize(self):
        return self.value
