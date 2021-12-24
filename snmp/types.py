__all__ = [
    "INTEGER", "OCTET_STRING", "NULL", "OBJECT_IDENTIFIER", "SEQUENCE",
    "Asn1Encodable", "Integer", "OctetString", "Null", "OID",
    "Constructed", "Sequence",
]

from snmp.ber import *

INTEGER             = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 2)
OCTET_STRING        = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 4)
NULL                = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 5)
OBJECT_IDENTIFIER   = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 6)
SEQUENCE            = Identifier(CLASS_UNIVERSAL, STRUCTURE_CONSTRUCTED, 16)

class Asn1Encodable:
    @classmethod
    def decode(cls, data, leftovers=False, copy=True, **kwargs):
        result = decode(data, expected=cls.TYPE, leftovers=leftovers, copy=copy)

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

class Integer(Asn1Encodable):
    SIGNED = True
    SIZE = 4
    TYPE = INTEGER

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "{}({})".format(self.__class__.__name__, self.value)

    @classmethod
    def deserialize(cls, data):
        for i in range(len(data) - cls.SIZE):
            if data[i] != 0:
                msg = "Encoding too large for {}".format(cls.__name__)
                raise ParseError(msg)

        return cls(int.from_bytes(data, "big", signed=cls.SIGNED))

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

class OctetString(Asn1Encodable):
    TYPE = OCTET_STRING

    MIN_SIZE = 0
    MAX_SIZE = 0xffff
    INVALID_SIZES = ()

    def __init__(self, data=b''):
        self.data = data

    def __repr__(self):
        return "{}({})".format(self.__class__.__name__, self.data)

    @classmethod
    def deserialize(cls, data):
        if len(data) < cls.MIN_SIZE:
            msg = "Encoded {} may not be less than {} bytes long"
            raise ParseError(msg.format(cls.__name__, cls.MIN_SIZE))
        elif len(data) > cls.MAX_SIZE:
            msg = "Encoded {} may not be more than {} bytes long"
            raise ParseError(msg.format(cls.__name__, cls.MAX_SIZE))
        elif len(data) in cls.INVALID_SIZES:
            msg = "Encoded {} not permitted to be {} bytes long"
            raise ParseError(msg.format(cls.__name__, len(data)))

        return cls.parse(data)

    @classmethod
    def parse(cls, data):
        return cls(data)

    def serialize(self):
        return self.data

class Null(Asn1Encodable):
    TYPE = NULL

    def __repr__(self):
        return self.__class__.__name__

    @classmethod
    def deserialize(cls, data):
        return cls()

    def serialize(self):
        return b''

class OID(Asn1Encodable):
    TYPE = OBJECT_IDENTIFIER

    def __init__(self, oid="0.0", raw=None):
        self.oid = oid
        self._raw = raw

    def __repr__(self):
        return "{}(\"{}\")".format(self.__class__.__name__, self.oid)

    @property
    def raw(self):
        if self._raw is None:
            words = self.oid.split(".")

            if words[0] == '':
                words.pop(0)

            nums = [int(word) for word in words]

            while(len(nums) < 2):
                nums.append(0)

            nums[0] *= 40
            nums[1] += nums[0]
            nums.pop(0)

            raw = bytearray()
            for num in nums:
                if num < 0x80:
                    raw.append(num)
                else:
                    scratch = bytearray()
                    while num > 0x7f:
                        scratch.append(num & 0x7f)
                        num >>= 7

                    scratch.append(num)
                    for i in range(1, len(scratch)):
                        scratch[i] |= 0x80

                    scratch.reverse()
                    raw.extend(scratch)

            self._raw = bytes(raw)
        return self._raw

    @classmethod
    def deserialize(cls, data):
        raw = bytes(data)
        data = iter(data)

        try:
            oid = list(divmod(next(data), 40))
        except StopIteration as err:
            raise ParseError("Empty OID") from err

        value = 0
        for byte in data:
            value |= byte & 0x7f
            if byte & 0x80:
                value <<= 7
            else:
                oid.append(value)
                value = 0

        if value:
            raise ParseError("OID ended unexpectedly")

        return cls(".".join([str(num) for num in oid]), raw=raw)

    def serialize(self):
        return self.raw

class Constructed(Asn1Encodable):
    @property
    def objects(self):
        raise AttributeError(
            "{} does not override .objects".format(self.__class__.__name__)
        )

    def serialize(self):
        return b''.join([item.encode() for item in self.objects])

class Sequence(Constructed):
    TYPE = SEQUENCE
