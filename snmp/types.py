__all__ = [
    "INTEGER", "OCTET_STRING", "NULL", "OBJECT_IDENTIFIER", "SEQUENCE",
    "Asn1Encodable", "Integer", "OctetString", "Null", "OID",
    "Constructed", "Sequence",
]

from snmp.ber import *
from snmp.exception import *
from snmp.utils import typename

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
        errmsg = "{} does not implement deserialize()"
        raise IncompleteChildClass(errmsg.format(typename(cls, True)))

    def serialize(self):
        errmsg = "{} does not implement serialize()"
        raise IncompleteChildClass(errmsg.format(typename(self, True)))

class Integer(Asn1Encodable):
    SIGNED = True
    SIZE = 4
    TYPE = INTEGER

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "{}({})".format(typename(self), self.value)

    @classmethod
    def deserialize(cls, data):
        for i in range(len(data) - cls.SIZE):
            if data[i] != 0:
                msg = "Encoding too large for {}".format(typename(cls))
                raise ParseError(msg)

        return cls(int.from_bytes(data, "big", signed=cls.SIGNED))

    def serialize(self):
        try:
            encoding = self.value.to_bytes(self.SIZE, "big", signed=self.SIGNED)
        except OverflowError as err:
            raise ValueError(err) from err

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
        return "{}({})".format(typename(self), self.data)

    @classmethod
    def deserialize(cls, data):
        if len(data) < cls.MIN_SIZE:
            msg = "Encoded {} may not be less than {} bytes long"
            raise ParseError(msg.format(typename(cls), cls.MIN_SIZE))
        elif len(data) > cls.MAX_SIZE:
            msg = "Encoded {} may not be more than {} bytes long"
            raise ParseError(msg.format(typename(cls), cls.MAX_SIZE))
        elif len(data) in cls.INVALID_SIZES:
            msg = "Encoded {} not permitted to be {} bytes long"
            raise ParseError(msg.format(typename(cls), len(data)))

        return cls.parse(data)

    @classmethod
    def parse(cls, data):
        return cls(data)

    def serialize(self):
        return self.data

class Null(Asn1Encodable):
    TYPE = NULL

    def __repr__(self):
        return "{}()".format(typename(self))

    @classmethod
    def deserialize(cls, data):
        return cls()

    def serialize(self):
        return b''

class UInt32Sequence:
    DOT = '.'

    def __init__(self, *nums):
        assert all(0 <= n < (1 << 32) for n in nums)
        self.nums = nums

    def __repr__(self):
        return "{}{}".format(typename(self), self.nums)

    def __str__(self):
        return self.DOT.join(str(n) for n in self.nums)

    def __eq__(a, b):
        return a.nums.__eq__(b.nums)

    def __getitem__(self, idx):
        return self.nums.__getitem__(idx)

    def __len__(self):
        return self.nums.__len__()

class OID(Asn1Encodable, UInt32Sequence):
    MULT = 40
    MAXLEN = 128
    TYPE = OBJECT_IDENTIFIER

    class BadPrefix(IncomingMessageError):
        pass

    class IndexDecodeError(IncomingMessageError):
        pass

    def __init__(self, *nums):
        if len(nums) > self.MAXLEN:
            errmsg = "{} may not contain more than {} sub-identifiers"
            raise ValueError(errmsg.format(typename(self), self.MAXLEN))

        super().__init__(*nums)

    @classmethod
    def parse(cls, oid):
        if oid.startswith(cls.DOT):
            oid = oid[len(cls.DOT):]

        try:
            nums = tuple(int(num) for num in oid.split(cls.DOT))
        except ValueError as e:
            raise ValueError("Invalid OID string: \"{}\"".format(oid)) from e

        try:
            if nums[0] > 2:
                errmsg = "{} may not begin with {}"
                raise ValueError(errmsg.format(typename(cls), nums[0]))

            if nums[1] >= cls.MULT:
                errmsg = "second number in {} must be less than {}"
                raise ValueError(errmsg.format(typename(cls), nums[1]))
        except IndexError as e:
            errmsg = "OID \"{}\" contains fewer than 2 sub-identifiers"
            raise ValueError(errmsg.format(oid)) from e

        if any(n < 0 for n in nums):
            raise ValueError("\"{}\" contains a negative sub-identifier")
        elif any(n >= (1 << 32) for n in nums):
            errmsg = "OID \"{}\" contains a sub-identifier that is too large"
            raise ValueError(errmsg.format(oid))

        return cls(*nums)

    def extend(self, *nums):
        nums = self.nums + nums
        return type(self)(*nums)

    def extractIndex(self, prefix):
        if self.startswith(prefix):
            return self.nums[len(prefix):]

    def startswith(self, prefix):
        return prefix.nums == self.nums[:len(prefix)]

    @classmethod
    def deserialize(cls, data):
        data = iter(data)

        try:
            oid = list(divmod(next(data), cls.MULT))
        except StopIteration as err:
            raise ParseError("Empty {}".format(typename(cls))) from err

        value = 0
        for byte in data:
            value |= byte & 0x7f
            if byte & 0x80:
                value <<= 7
                if value >= (1 << 32):
                    raise ParseError("Sub-identifier out of range")
            else:
                oid.append(value)
                value = 0

        if value:
            raise ParseError("OID ended unexpectedly")

        return cls(*oid)

    def serialize(self):
        def append(bytearr, num):
            if num < 0x80:
                bytearr.append(num)
            else:
                flag = 0
                tmp = bytearray()

                while num:
                    tmp.append((num & 0x7f) | flag)
                    flag = 0x80
                    num >>= 7

                tmp.reverse()
                bytearr.extend(tmp)

        try:
            first = self.nums[0]
        except IndexError:
            return b"\x00"

        try:
            second = self.nums[1]
        except IndexError:
            second = 0

        encoding = bytearray()
        append(encoding, first * self.MULT | second)
        for number in self.nums[2:]:
            append(encoding, number)

        return bytes(encoding)

class Constructed(Asn1Encodable):
    @property
    def objects(self):
        errmsg = "{} does not implement .objects"
        raise IncompleteChildClass(errmsg.format(typename(self, True)))

    def serialize(self):
        return b''.join([item.encode() for item in self.objects])

class Sequence(Constructed):
    TYPE = SEQUENCE
