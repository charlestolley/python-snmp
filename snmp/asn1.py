__all__ = ["INTEGER", "OCTET_STRING", "NULL", "OBJECT_IDENTIFIER", "SEQUENCE"]

from snmp.ber import *
from snmp.exception import *
from snmp.utils import *

class ASN1:
    class DeserializeError(SNMPException):
        def __init__(self, msg, etype = ParseError):
            self.etype = etype
            self.msg = msg

        def reraise(self, data, tail = None):
            raise self.etype(self.msg, data, tail) from self

    @classmethod
    def checkTag(cls, tag, data, tail = None):
        if tag != cls.TAG:
            errmsg = f"{tag} does not match the expected type: {cls.TAG}"
            raise ParseError(errmsg, data, tail)

    @classmethod
    def decode(cls, data, **kwargs):
        tag, body, tail = decode(data)
        cls.checkTag(tag, data, tail)

        try:
            return cls.deserialize(body, **kwargs), tail
        except ASN1.DeserializeError as err:
            err.reraise(data, tail)

    @classmethod
    def decodeExact(cls, data, **kwargs):
        tag, body = decodeExact(data)
        cls.checkTag(tag, data)

        try:
            return cls.deserialize(body, **kwargs)
        except ASN1.DeserializeError as err:
            err.reraise(data)

    def encode(self):
        return encode(self.TAG, self.serialize())

    @classmethod
    def deserialize(cls, data):
        raise NotImplementedError()

    def serialize(self):
        raise NotImplementedError()

class Constructed(ASN1):
    def __eq__(self, other):
        if not isinstance(other, Constructed):
            return NotImplemented

        if type(self) != type(other) or len(self) != len(other):
            return False

        for left, right in zip(self, other):
            if left != right:
                return False

        return True

    def __iter__(self):
        raise NotImplementedError()

    def __len__(self):
        raise NotImplementedError()

    def serialize(self):
        return b"".join([obj.encode() for obj in self])

class Primitive(ASN1):
    def asOID(self, implied = False):
        raise NotImplementedError()

    @classmethod
    def fromOID(cls, nums, implied = False):
        raise NotImplementedError()

class INTEGER(Primitive):
    BYTEORDER = "big"
    TAG = Tag(2)

    def __init__(self, value):
        self._value = value

    def __eq__(self, other):
        if not isinstance(other, INTEGER):
            return NotImplemented

        return self.value == other.value and self.TAG == other.TAG

    def __repr__(self):
        return f"{typename(self)}({self.value})"

    @property
    def value(self):
        return self._value

    @staticmethod
    def bitCount(value):
        if value < 0:
            value = -value - 1

        return value.bit_length()

    @classmethod
    def construct(cls, value):
        return cls(value)

    @classmethod
    def deserialize(cls, data):
        value = int.from_bytes(data, cls.BYTEORDER, signed=True)
        return cls.construct(value)

    def serialize(self):
        # equivalent to (N + 8) // 8
        # the reason it's not (N + 7) is that ASN.1 always includes a sign bit
        nbytes = (self.bitCount(self.value) // 8) + 1
        return self.value.to_bytes(nbytes, self.BYTEORDER, signed=True)

    def asOID(self, implied = False):
        yield self.value

    @classmethod
    def fromOID(cls, nums, implied = False):
        return cls(next(nums))

class OCTET_STRING(Primitive):
    TAG = Tag(4)

    def __init__(self, data = b""):
        self._data = data

    def __eq__(self, other):
        if not isinstance(other, OCTET_STRING):
            return NotImplemented

        return self.data == other.data and self.TAG == other.TAG

    def __repr__(self):
        return f"{typename(self)}({repr(self.data)})"

    @property
    def data(self):
        return self._data

    def asOID(self, implied = False):
        if not implied:
            yield len(self.data)

        yield from self.data

    @classmethod
    def fromOID(cls, nums, implied = False):
        if implied:
            data = bytes(nums)
        else:
            length = next(nums)
            data = bytes([next(nums) for _ in range(length)])

        return cls(data)

    @classmethod
    def construct(cls, data):
        return cls(data[:])

    @classmethod
    def deserialize(cls, data, copy = True):
        if copy:
            return cls.construct(data[:])
        else:
            return cls.construct(data)

    def serialize(self):
        return self.data

class NULL(Primitive):
    TAG = Tag(5)

    def __eq__(self, other):
        if not isinstance(other, NULL):
            return NotImplemented

        return self.TAG == other.TAG

    def __repr__(self):
        return f"{typename(self)}()"

    def asOID(self, implied = False):
        return ()

    @classmethod
    def fromOID(cls, nums, implied = False):
        return cls()

    @classmethod
    def deserialize(cls, data):
        return cls()

    def serialize(self):
        return b""

class OBJECT_IDENTIFIER(Primitive):
    TAG = Tag(6)

    class BadPrefix(SNMPException):
        pass

    class IndexDecodeError(SNMPException):
        pass

    class CountingIterator:
        def __init__(self, nums, count = 0):
            self.count = count
            self.wrapped = iter(nums[count:])

        def __iter__(self):
            return self

        def __next__(self):
            item = next(self.wrapped)
            self.count += 1
            return item

    def __init__(self, *subidentifiers):
        first = 0
        second = 0

        try:
            first = subidentifiers[0]
            second = subidentifiers[1]
        except IndexError:
            pass

        if first > 2:
            raise ValueError("The first subidentifier must be less than 3")
        elif second >= 40:
            raise ValueError("The second subidentifier must be less than 40")

        if any(map(lambda x: x < 0, subidentifiers)):
            raise ValueError("Sub-identifiers may not be negative")

        self.subidentifiers = subidentifiers

    def __eq__(self, other):
        if not isinstance(other, OBJECT_IDENTIFIER):
            return NotImplemented

        return self.subidentifiers == other.subidentifiers

    def __lt__(self, other):
        return self.subidentifiers < other.subidentifiers

    def __getitem__(self, index):
        return self.subidentifiers.__getitem__(index)

    def __hash__(self):
        return self.subidentifiers.__hash__()

    def __iter__(self):
        return iter(self.subidentifiers)

    def __len__(self):
        return len(self.subidentifiers)

    def __repr__(self):
        args = ", ".join(str(i) for i in self.subidentifiers)
        return f"{typename(self)}({args})"

    def __str__(self):
        return ".".join(str(i) for i in  self.subidentifiers)

    @classmethod
    def parse(cls, oid):
        numbers = oid.split(".")

        if numbers[0] == "":
            numbers = numbers[1:]

        try:
            return cls(*(int(n) for n in numbers))
        except ValueError as err:
            raise ValueError(f"\"{oid}\": {err}") from err

    def asOID(self, implied = False):
        if not implied:
            yield len(self.subidentifiers)

        yield from self.subidentifiers

    @classmethod
    def fromOID(cls, nums, implied = False):
        if implied:
            subidentifiers = nums
        else:
            length = next(nums)
            subidentifiers = [next(nums) for i in range(length)]

        return cls(*subidentifiers)

    def extend(self, *subidentifiers):
        return self.__class__(*self.subidentifiers, *subidentifiers)

    def startswith(self, prefix):
        return self.subidentifiers[:len(prefix)] == prefix[:]

    def decodeIndex(self, prefix, *types, implied = False):
        if not self.startswith(prefix):
            errmsg = f"\"{self}\" does not begin with \"{prefix}\""
            raise self.BadPrefix(errmsg)

        nums = self.CountingIterator(self.subidentifiers, len(prefix))

        index = []
        for cls in types[:-1]:
            index.append(self.decodeIndexField(nums, cls))

        for cls in types[-1:]:
            index.append(self.decodeIndexField(nums, cls, implied=implied))

        try:
            next(nums)
        except StopIteration:
            pass
        else:
            errmsg = f"Only {nums.count-1} of {len(self)}" \
                f" sub-identifiers were consumed: \"{self}\""
            raise self.IndexDecodeError(errmsg)

        return tuple(index)

    def decodeIndexField(self, nums, cls, implied = False):
        position = nums.count

        try:
            return cls.fromOID(nums, implied=implied)
        except StopIteration as err:
            impstr = "IMPLIED " if implied else ""
            errmsg = f"Incomplete {impstr}{typename(cls)}" \
                f" at position {position}: {self}"
            raise OBJECT_IDENTIFIER.IndexDecodeError(errmsg) from err
        except ValueError as err:
            impstr = "IMPLIED " if implied else ""
            errmsg = f"Failed to decode {impstr}{typename(cls)}" \
                f" at position {position}: {self}: {err.args[0]}"
            raise OBJECT_IDENTIFIER.IndexDecodeError(errmsg) from err

    def withIndex(self, *index, implied = False):
        oid = self

        for obj in index[:-1]:
            oid = oid.extend(*obj.asOID())

        for obj in index[-1:]:
            oid = oid.extend(*obj.asOID(implied=implied))

        return oid

    @classmethod
    def construct(cls, *subidentifiers):
        try:
            return cls(*subidentifiers)
        except ValueError as err:
            raise ASN1.DeserializeError(err.args[0]) from err

    @classmethod
    def deserialize(cls, data):
        stream = iter(data)

        try:
            oid = list(divmod(next(stream), 40))
        except StopIteration as err:
            raise ASN1.DeserializeError("Empty") from err

        value = 0
        for byte in stream:
            value |= byte & 0x7f
            if byte & 0x80:
                value <<= 7
            else:
                oid.append(value)
                value = 0

        if value:
            errmsg = f"{typename(cls)} encoding ended mid-subidentifier"
            raise ASN1.DeserializeError(errmsg)

        return cls.construct(*oid)

    @staticmethod
    def serializeSubIdentifier(bytearr, num):
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

    def serialize(self):
        try:
            first = self.subidentifiers[0]
        except IndexError:
            return b"\x00"

        try:
            second = self.subidentifiers[1]
        except IndexError:
            second = 0

        encoding = bytearray()
        self.serializeSubIdentifier(encoding, first * 40 | second)
        for subidentifier in self.subidentifiers[2:]:
            self.serializeSubIdentifier(encoding, subidentifier)

        return bytes(encoding)

class SEQUENCE(Constructed):
    TAG = Tag(16, True)
