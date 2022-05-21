__all__ = [
    "INTEGER", "OCTET_STRING", "NULL", "OBJECT_IDENTIFIER", "SEQUENCE",
    "Asn1Encodable", "Integer", "OctetString", "Null", "OID",
    "Constructed", "Sequence",
]

import re
from snmp.ber import *
from snmp.exception import *
from snmp.utils import typename

INTEGER             = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 2)
OCTET_STRING        = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 4)
NULL                = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 5)
OBJECT_IDENTIFIER   = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 6)
SEQUENCE            = Identifier(CLASS_UNIVERSAL, STRUCTURE_CONSTRUCTED, 16)

class Asn1Encodable:
    def __eq__(a, b):
        return a.equals(b) if type(a) == type(b) else False

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

    def equals(a, b):
        errmsg = "{} does not support comparison"
        raise IncompleteChildClass(errmsg.format(typename(a, True)))

    def appendToOID(self, oid):
        errmsg = "{} does not implement appendToOID()"
        raise IncompleteChildClass(errmsg.format(typename(self, True)))

    @classmethod
    def decodeFromOID(cls, nums):
        errmsg = "{} does not implement decodeFromOID()"
        raise IncompleteChildClass(errmsg.format(typename(cls, True)))

    @classmethod
    def deserialize(cls, data):
        errmsg = "{} does not implement deserialize()"
        raise IncompleteChildClass(errmsg.format(typename(cls, True)))

    def serialize(self):
        errmsg = "{} does not implement serialize()"
        raise IncompleteChildClass(errmsg.format(typename(self, True)))

class Integer(Asn1Encodable):
    BYTEORDER = "big"
    SIGNED = True
    SIZE = 4
    TYPE = INTEGER

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "{}({})".format(typename(self), self.value)

    def equals(a, b):
        return a.value == b.value

    def appendToOID(self, oid):
        return oid.extend(self.value)

    @classmethod
    def decodeFromOID(cls, nums):
        value = next(nums)

        try:
            value.to_bytes(cls.SIZE, cls.BYTEORDER, signed=cls.SIGNED)
        except OverflowError as err:
            errmsg = "{} value out of range: {}".format(typename(cls), value)
            raise OID.IndexDecodeError(errmsg) from err

        return cls(value)

    @classmethod
    def deserialize(cls, data):
        for i in range(len(data) - cls.SIZE):
            if data[i] != 0:
                msg = "Encoding too large for {}".format(typename(cls))
                raise ParseError(msg)

        return cls(int.from_bytes(data, cls.BYTEORDER, signed=cls.SIGNED))

    def serialize(self):
        try:
            encoding = self.value.to_bytes(
                self.SIZE,
                self.BYTEORDER,
                signed=self.SIGNED
            )
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

    def equals(a, b):
        return a.data == b.data

    def appendToOID(self, oid):
        return oid.extend(len(self.data), *self.data)

    @classmethod
    def decodeFromOID(cls, nums):
        length = next(nums)
        data = bytearray(length)

        for i in range(length):
            byte = next(nums)

            try:
                data[i] = byte
            except ValueError as err:
                errmsg = "Sub-identifier does not fit within a single octet: {}"
                raise OID.IndexDecodeError(errmsg.format(byte)) from err

        return cls(bytes(data))

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

    def equals(a, b):
        return True

    def appendToOID(self, oid):
        return oid

    @classmethod
    def decodeFromOID(cls, nums):
        errmsg = "{} may not be used as an OID index"
        raise TypeError(errmsg.format(typename(cls)))

    @classmethod
    def deserialize(cls, data):
        return cls()

    def serialize(self):
        return b''

class OID(Asn1Encodable):
    DOT = '.'
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

        assert all(0 <= n < (1 << 32) for n in nums)
        self.nums = nums

    def __repr__(self):
        return "{}{}".format(typename(self), self.nums)

    def __str__(self):
        return self.DOT.join(str(n) for n in self.nums)

    def __getitem__(self, idx):
        return self.nums.__getitem__(idx)

    def __len__(self):
        return self.nums.__len__()

    def tryDecode(self, nums, cls):
        try:
            return cls.decodeFromOID(nums)
        except StopIteration as err:
            errmsg = "Incomplete {} index".format(typename(cls))
            raise OID.IndexDecodeError(errmsg) from err

    FIRST = re.compile(r"^\.?(\d+|$)")
    REGEX = re.compile(r"\.(\d+)")

    @classmethod
    def parse(cls, oid):
        match = cls.FIRST.match(oid)

        if match is None:
            raise ValueError(f"Invalid OID string: {oid}")

        nums = []
        if match.group(1):
            while match is not None:
                nums.append(int(match.group(1)))
                index = match.end()
                match = cls.REGEX.match(oid, index)

            if index != len(oid):
                raise ValueError(f"Trailing characters in OID string: {oid}")

        try:
            if nums[0] > 2:
                errmsg = "{} may not begin with {}"
                raise ValueError(errmsg.format(typename(cls), nums[0]))

            if nums[1] >= cls.MULT:
                errmsg = "second number in {} must be less than {}"
                raise ValueError(errmsg.format(typename(cls), nums[1]))
        except IndexError as err:
            pass

        if any(n < 0 for n in nums):
            raise ValueError("\"{}\" contains a negative sub-identifier")
        elif any(n >= (1 << 32) for n in nums):
            errmsg = "OID \"{}\" contains a sub-identifier that is too large"
            raise ValueError(errmsg.format(oid))

        return cls(*nums)

    def extend(self, *nums):
        nums = self.nums + nums
        return type(self)(*nums)

    def appendIndex(self, *index):
        oid = self
        for obj in index:
            oid = obj.appendToOID(oid)

        return oid

    def extractIndex(self, prefix, *types):
        nums = iter(self.nums)
        for subid in prefix:
            try:
                match = (subid == next(nums))
            except StopIteration as err:
                errmsg = "\"{}\" is shorter than the given prefix \"{}\""
                raise self.BadPrefix(errmsg.format(self, prefix)) from err

            if not match:
                errmsg = "\"{}\" does not begin with \"{}\""
                raise self.BadPrefix(errmsg.format(self, prefix))

        index = None
        if len(types) == 1:
            index = self.tryDecode(nums, types[0])
        elif types:
            index = [None] * len(types)
            for i, cls in enumerate(types):
                index[i] = self.tryDecode(nums, cls)

            index = tuple(index)

        try:
            next(nums)
        except StopIteration:
            return index
        else:
            raise self.IndexDecodeError("Not all sub-identifiers were consumed")

    def equals(a, b):
        return a.nums == b.nums

    def appendToOID(self, oid):
        return oid.extend(len(self.nums), *self.nums)

    @classmethod
    def decodeFromOID(cls, nums):
        length = next(nums)
        subids = [0] * length

        for i in range(length):
            subids[i] = next(nums)

        return cls(*subids)

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
    def equals(a, b):
        if len(a) == len(b):
            for left, right in zip(a.objects, b.objects):
                if left != right:
                    return False

        return True

    def __len__(self):
        errmsg = "{} does not implement __len__"
        raise IncompleteChildClass(errmsg.format(typename(self, True)))

    @property
    def objects(self):
        errmsg = "{} does not implement .objects"
        raise IncompleteChildClass(errmsg.format(typename(self, True)))

    def serialize(self):
        return b''.join([item.encode() for item in self.objects])

class Sequence(Constructed):
    TYPE = SEQUENCE
