__all__ = [
    "INTEGER", "OCTET_STRING", "NULL", "OBJECT_IDENTIFIER", "SEQUENCE",
    "Asn1Encodable","Primitive", "Constructed",
    "Integer", "OctetString", "Null", "OID", "Sequence",
]

from abc import abstractmethod
import re
from snmp.ber import *
from snmp.exception import *
from snmp.typing import *
from snmp.utils import *

INTEGER             = Identifier(Class.UNIVERSAL, Structure.PRIMITIVE, 2)
OCTET_STRING        = Identifier(Class.UNIVERSAL, Structure.PRIMITIVE, 4)
NULL                = Identifier(Class.UNIVERSAL, Structure.PRIMITIVE, 5)
OBJECT_IDENTIFIER   = Identifier(Class.UNIVERSAL, Structure.PRIMITIVE, 6)
SEQUENCE            = Identifier(Class.UNIVERSAL, Structure.CONSTRUCTED, 16)

Bool = Literal[False, True]
TEncodable      = TypeVar("TEncodable",     bound="Asn1Encodable")
TPrimitive      = TypeVar("TPrimitive",     bound="Primitive")
TInteger        = TypeVar("TInteger",       bound="Integer")
TOctetString    = TypeVar("TOctetString",   bound="OctetString")
TNull           = TypeVar("TNull",          bound="Null")
TOID            = TypeVar("TOID",           bound="OID")

class Asn1Encodable:
    TYPE: ClassVar[Identifier]

    def __eq__(self, other: Any) -> bool:
        if type(self) == type(other):
            return self.equals(other)
        else:
            return NotImplemented

    @overload
    @classmethod
    def decode(
        cls: Type[TEncodable],
        data: Asn1Data,
    ) -> TEncodable:
        ...

    @overload
    @classmethod
    def decode(
        cls: Type[TEncodable],
        data: Asn1Data,
        leftovers: bool = False,
        copy: bool = True,
        **kwargs: Any,
    ) -> Union[TEncodable, Tuple[TEncodable, subbytes]]:
        ...

    @classmethod
    def decode(
        cls: Type[TEncodable],
        data: Asn1Data,
        leftovers: bool = False,
        copy: bool = True,
        **kwargs: Any,
    ) -> Union[TEncodable, Tuple[TEncodable, subbytes]]:
        _copy: Bool = copy
        if leftovers:
            encoding, tail = decode(data, cls.TYPE, True, _copy)
            return cls.deserialize(encoding, **kwargs), tail
        else:
            encoding = decode(data, cls.TYPE, False, _copy)
            return cls.deserialize(encoding, **kwargs)

    def encode(self) -> bytes:
        return encode(self.TYPE, self.serialize())

    @abstractmethod
    def equals(self: TEncodable, other: TEncodable) -> bool:
        ...

    @classmethod
    @abstractmethod
    def deserialize(cls: Type[TEncodable], data: Asn1Data) -> TEncodable:
        ...

    @abstractmethod
    def serialize(self) -> bytes:
        ...

class Primitive(Asn1Encodable):
    @abstractmethod
    def appendToOID(self, oid: TOID, implied: bool = False) -> TOID:
        ...

    @classmethod
    @abstractmethod
    def decodeFromOID(
        cls: Type[TPrimitive],
        nums: Iterator[int],
        implied: bool = False,
    ) -> TPrimitive:
        ...

class Integer(Primitive):
    TYPE = INTEGER

    BITS:       ClassVar[int]               = 32
    BYTEORDER:  ClassVar[Literal["big"]]    = "big"
    SIGNED:     ClassVar[bool]              = True

    def __init__(self, value: int) -> None:
        self._value = value

    def __repr__(self) -> str:
        return f"{typename(self)}({self.value})"

    @property
    def value(self) -> int:
        return self._value

    def equals(self, other: "Integer") -> bool:
        return self.value == other.value

    def appendToOID(self, oid: TOID, implied: bool = False) -> TOID:
        return oid.extend(self.value)

    @classmethod
    def inRange(cls, value: int) -> bool:
        assert isinstance(cls.SIGNED, bool)
        return value.bit_length() <= cls.BITS - cls.SIGNED + (value < 0)

    @classmethod
    def decodeFromOID(
        cls: Type[TInteger],
        nums: Iterator[int],
        implied: bool = False,
    ) -> TInteger:
        value = next(nums)

        if not cls.inRange(value):
            errmsg = f"{typename(cls)} value out of range: {value}"
            raise OID.IndexDecodeError(errmsg)

        return cls(value)

    @classmethod
    def deserialize(cls: Type[TInteger], data: Asn1Data) -> TInteger:
        value = int.from_bytes(data, cls.BYTEORDER, signed=cls.SIGNED)

        if not cls.inRange(value):
            raise ParseError(f"Encoding too large for {typename(cls)}")

        return cls(value)

    def serialize(self) -> bytes:
        assert self.inRange(self.value)

        # equivalent to (N + 8) // 8
        # the reason it's not (N + 7) is that ASN.1 always includes a sign bit
        nbytes = (self.value.bit_length() // 8) + 1
        return self.value.to_bytes(nbytes, self.BYTEORDER, signed=True)

class OctetString(Primitive):
    TYPE = OCTET_STRING

    MIN_SIZE:       ClassVar[int]               = 0
    MAX_SIZE:       ClassVar[int]               = 0xffff
    INVALID_SIZES:  ClassVar[Tuple[int, ...]]   = ()

    def __init__(self, data: Asn1Data = b"") -> None:
        self._data = data

    def __repr__(self) -> str:
        return f"{typename(self)}({self.data!r})"

    @property
    def data(self) -> Asn1Data:
        return self._data

    def equals(self, other: "OctetString") -> bool:
        return self.data == other.data

    def appendToOID(self, oid: TOID, implied: bool = False) -> TOID:
        if not implied:
            oid = oid.extend(len(self.data))

        return oid.extend(*self.data)

    @classmethod
    def decodeFromOID(
        cls: Type[TOctetString],
        nums: Iterator[int],
        implied: bool = False,
    ) -> TOctetString:
        if implied:
            length = OID.MAXLEN
        elif cls.MIN_SIZE == cls.MAX_SIZE:
            length = cls.MAX_SIZE
        else:
            length = next(nums)

        data = bytearray()
        while len(data) < length:
            try:
                byte = next(nums)
            except StopIteration:
                if implied:
                    break
                else:
                    raise

            try:
                data.append(byte)
            except ValueError as err:
                errmsg = "Sub-identifier is too large for type \"{}\": {}"
                raise OID.IndexDecodeError(
                    errmsg.format(typename(cls), byte)
                ) from err

        return cls.interpret(bytes(data))

    @classmethod
    def deserialize(cls: Type[TOctetString], data: Asn1Data) -> TOctetString:
        if len(data) < cls.MIN_SIZE:
            msg = "Encoded {} may not be less than {} bytes long"
            raise ParseError(msg.format(typename(cls), cls.MIN_SIZE))
        elif len(data) > cls.MAX_SIZE:
            msg = "Encoded {} may not be more than {} bytes long"
            raise ParseError(msg.format(typename(cls), cls.MAX_SIZE))
        elif len(data) in cls.INVALID_SIZES:
            msg = "Encoded {} not permitted to be {} bytes long"
            raise ParseError(msg.format(typename(cls), len(data)))

        return cls.interpret(data)

    @classmethod
    def interpret(cls: Type[TOctetString], data: Asn1Data) -> TOctetString:
        return cls(data)

    def serialize(self) -> bytes:
        data = self.data
        if len(data) < self.MIN_SIZE:
            msg = "Encoded {} may not be less than {} bytes long"
            raise ValueError(msg.format(typename(self), self.MIN_SIZE))
        elif len(data) > self.MAX_SIZE:
            msg = "Encoded {} may not be more than {} bytes long"
            raise ValueError(msg.format(typename(self), self.MAX_SIZE))
        elif len(data) in self.INVALID_SIZES:
            msg = "Encoded {} not permitted to be {} bytes long"
            raise ValueError(msg.format(typename(self), len(data)))

        return data[:] if isinstance(data, subbytes) else data

class Null(Primitive):
    TYPE = NULL

    def __repr__(self) -> str:
        return f"{typename(self)}()"

    def equals(self, other: "Null") -> bool:
        return True

    def appendToOID(self, oid: TOID, implied: bool = False) -> TOID:
        return oid

    @classmethod
    def decodeFromOID(
        cls: Type[TNull],
        nums: Iterator[int],
        implied: bool = False,
    ) -> TNull:
        return cls()

    @classmethod
    def deserialize(cls: Type[TNull], data: Asn1Data) -> TNull:
        return cls()

    def serialize(self) -> bytes:
        return b""

class OID(Primitive):
    TYPE = OBJECT_IDENTIFIER

    DOT:    ClassVar[str] = "."
    MULT:   ClassVar[int] = 40
    MAXLEN: ClassVar[int] = 128

    class BadPrefix(IncomingMessageError):
        pass

    class IndexDecodeError(IncomingMessageError):
        pass

    def __init__(self, *nums: int) -> None:
        if len(nums) > self.MAXLEN:
            errmsg = "{} may not contain more than {} sub-identifiers"
            raise ValueError(errmsg.format(typename(self), self.MAXLEN))

        assert all(0 <= n < (1 << 32) for n in nums)
        self.nums = nums

    def __repr__(self) -> str:
        return f"{typename(self)}{self.nums}"

    def __str__(self) -> str:
        return self.DOT.join(str(n) for n in self.nums)

    @overload
    def __getitem__(self, idx: int) -> int:
        ...

    @overload
    def __getitem__(self, idx: slice) -> Tuple[int, ...]:
        ...

    def __getitem__(self,
        idx: Union[int, slice],
    ) -> Union[int, Tuple[int, ...]]:
        return self.nums.__getitem__(idx)

    def __hash__(self) -> int:
        return self.nums.__hash__()

    def __iter__(self) -> Iterator[int]:
        return self.nums.__iter__()

    def __len__(self) -> int:
        return self.nums.__len__()

    def __lt__(self, other: "OID") -> bool:
        return self.nums < other.nums

    @staticmethod
    def serializeSubIdentifier(bytearr: bytearray, num: int) -> None:
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

    def tryDecode(self,
        nums: Iterator[int],
        cls: Type[TPrimitive],
        implied: bool = False,
    ) -> TPrimitive:
        try:
            return cls.decodeFromOID(nums, implied=implied)
        except StopIteration as err:
            errmsg = f"Incomplete {typename(cls)} index"
            raise OID.IndexDecodeError(errmsg) from err

    FIRST = re.compile(r"^\.?(\d+|$)")
    REGEX = re.compile(r"\.(\d+)")

    @classmethod
    def parse(cls: Type[TOID], oid: str) -> TOID:
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

    def appendIndex(self: TOID,
        *index: Primitive,
        implied: bool = False,
    ) -> TOID:
        oid = self
        for obj in index[:-1]:
            oid = obj.appendToOID(oid)

        for obj in index[-1:]:
            oid = obj.appendToOID(oid, implied=implied)

        return oid

    def extend(self: TOID, *nums: int) -> TOID:
        nums = self.nums + nums
        return type(self)(*nums)

    # TODO: I'm not sure whether the return type annotation is correct, or
    #       if the correct annotation even exists
    def extractIndex(self,
        prefix: "OID",
        *types: Type[TPrimitive],
        implied: bool = False,
    ) -> Tuple[TPrimitive, ...]:
        if len(self.nums) < len(prefix):
            errmsg = "\"{}\" is shorter than the given prefix \"{}\""
            raise self.BadPrefix(errmsg.format(self, prefix))

        if self.nums[:len(prefix)] != prefix.nums:
            errmsg = "\"{}\" does not begin with \"{}\""
            raise self.BadPrefix(errmsg.format(self, prefix))

        nums = iter(self.nums[len(prefix):])

        index = []
        for cls in types[:-1]:
            index.append(self.tryDecode(nums, cls))

        for cls in types[-1:]:
            index.append(self.tryDecode(nums, cls, implied=implied))

        try:
            next(nums)
        except StopIteration:
            pass
        else:
            errmsg = "Not all sub-identifiers were consumed"
            raise self.IndexDecodeError(errmsg)

        return tuple(index)

    def getIndex(self,
        prefix: "OID",
        cls: Type[TPrimitive] = Integer,    # type: ignore[assignment]
        implied: bool = False,
    ) -> TPrimitive:
        return self.extractIndex(prefix, cls, implied=implied)[0]

    def startswith(self, prefix: "OID") -> bool:
        return prefix.nums == self.nums[:len(prefix)]

    def equals(self, other: "OID") -> bool:
        return self.nums == other.nums

    def appendToOID(self, oid: TOID, implied: bool = False) -> TOID:
        if not implied:
            oid = oid.extend(len(self.nums))

        return oid.extend(*self.nums)

    @classmethod
    def decodeFromOID(
        cls: Type[TOID],
        nums: Iterator[int],
        implied: bool = False,
    ) -> TOID:
        if implied:
            length = OID.MAXLEN
        else:
            length = next(nums)

        subids = []
        for i in range(length):
            try:
                subids.append(next(nums))
            except StopIteration:
                if implied:
                    break
                else:
                    raise

        return cls(*subids)

    @classmethod
    def deserialize(cls: Type[TOID], data: Asn1Data) -> TOID:
        stream = iter(data)

        try:
            oid = list(divmod(next(stream), cls.MULT))
        except StopIteration as err:
            raise ParseError(f"Empty {typename(cls)}") from err

        value = 0
        for byte in stream:
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

    def serialize(self) -> bytes:
        try:
            first = self.nums[0]
        except IndexError:
            return b"\x00"

        try:
            second = self.nums[1]
        except IndexError:
            second = 0

        encoding = bytearray()
        self.serializeSubIdentifier(encoding, first * self.MULT | second)
        for number in self.nums[2:]:
            self.serializeSubIdentifier(encoding, number)

        return bytes(encoding)

class Constructed(Asn1Encodable):
    def equals(self, other: "Constructed") -> bool:
        if len(self) == len(other):
            for left, right in zip(self, other):
                if left != right:
                    return False

        return True

    @abstractmethod
    def __iter__(self) -> Iterator[Asn1Encodable]:
        ...

    @abstractmethod
    def __len__(self) -> int:
        ...

    def serialize(self) -> bytes:
        return b"".join([item.encode() for item in self])

class Sequence(Constructed):
    TYPE = SEQUENCE
