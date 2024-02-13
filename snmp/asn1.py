__all__ = [
    "ASN1", "Constructed", "Primitive",
    "INTEGER", "OCTET_STRING", "NULL", "OBJECT_IDENTIFIER", "SEQUENCE",
]

from snmp.ber import *
from snmp.exception import *
from snmp.typing import *
from snmp.utils import *

TASN1           = TypeVar("TASN1",          bound="ASN1")
TPrimitive      = TypeVar("TPrimitive",     bound="Primitive")
TINTEGER        = TypeVar("TINTEGER",       bound="INTEGER")
TOCTET_STRING   = TypeVar("TOCTET_STRING",  bound="OCTET_STRING")
TNULL           = TypeVar("TNULL",          bound="NULL")
TOID            = TypeVar("TOID",           bound="OBJECT_IDENTIFIER")

class ASN1:
    TAG: ClassVar[Tag]

    @overload
    @classmethod
    def decode(
        cls: Type[TASN1],
        data: Asn1Data,
    ) -> TASN1:
        ...

    @overload
    @classmethod
    def decode(
        cls: Type[TASN1],
        data: Asn1Data,
        leftovers: bool = False,
        copy: bool = True,
        **kwargs: Any,
    ) -> Union[TASN1, Tuple[TASN1, subbytes]]:
        ...

    @classmethod
    def decode(
        cls: Type[TASN1],
        data: Asn1Data,
        leftovers: bool = False,
        copy: bool = True,
        **kwargs: Any,
    ) -> Union[TASN1, Tuple[TASN1, subbytes]]:
        if leftovers:
            encoding, tail = decode(data, cls.TAG, True, copy)
            return cls.deserialize(encoding, **kwargs), tail
        else:
            encoding = decode(data, cls.TAG, False, copy)
            return cls.deserialize(encoding, **kwargs)

    def encode(self) -> bytes:
        return encode(self.TAG, self.serialize())

    @classmethod
    def deserialize(cls: Type[TASN1], data: Asn1Data) -> TASN1:
        raise NotImplementedError()

    def serialize(self) -> bytes:
        raise NotImplementedError()

class Constructed(ASN1):
    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Constructed):
            return NotImplemented

        if type(self) != type(other) or len(self) != len(other):
            return False

        for left, right in zip(self, other):
            if left != right:
                return False

        return True

    def __iter__(self) -> Iterator[ASN1]:
        raise NotImplementedError()

    def __len__(self) -> int:
        raise NotImplementedError()

    def serialize(self) -> bytes:
        return b"".join([obj.encode() for obj in self])

class Primitive(ASN1):
    def asOID(self, implied: bool = False) -> Iterable[int]:
        raise NotImplementedError()

    @classmethod
    def fromOID(
        cls: Type[TPrimitive],
        nums: Iterator[int],
        implied: bool = False,
    ) -> TPrimitive:
        raise NotImplementedError()

class INTEGER(Primitive):
    BYTEORDER: ClassVar[Literal["big"]] = "big"
    TAG = Tag(2)

    def __init__(self, value: int) -> None:
        self._value = value

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, INTEGER):
            return NotImplemented

        return self.value == other.value and self.TAG == other.TAG

    def __repr__(self) -> str:
        return f"{typename(self)}({self.value})"

    @property
    def value(self) -> int:
        return self._value

    @staticmethod
    def bitCount(value: int) -> int:
        if value < 0:
            value = -value - 1

        return value.bit_length()

    @classmethod
    def construct(cls: Type[TINTEGER], value: int) -> TINTEGER:
        return cls(value)

    @classmethod
    def deserialize(cls: Type[TINTEGER], data: Asn1Data) -> TINTEGER:
        value = int.from_bytes(data, cls.BYTEORDER, signed=True)
        return cls.construct(value)

    def serialize(self) -> bytes:
        # equivalent to (N + 8) // 8
        # the reason it's not (N + 7) is that ASN.1 always includes a sign bit
        nbytes = (self.bitCount(self.value) // 8) + 1
        return self.value.to_bytes(nbytes, self.BYTEORDER, signed=True)

    def asOID(self, implied: bool = False) -> Iterable[int]:
        yield self.value

    @classmethod
    def fromOID(
        cls: Type[TINTEGER],
        nums: Iterator[int],
        implied: bool = False,
    ) -> TINTEGER:
        try:
            return cls.construct(next(nums))
        except ParseError as err:
            raise OBJECT_IDENTIFIER.IndexDecodeError(*err.args) from err

class OCTET_STRING(Primitive):
    TAG = Tag(4)

    def __init__(self, data: bytes = b"") -> None:
        self._data = data

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, OCTET_STRING):
            return NotImplemented

        return self.data == other.data and self.TAG == other.TAG

    def __repr__(self) -> str:
        return f"{typename(self)}({repr(self.data)})"

    @property
    def data(self) -> bytes:
        return self._data

    def asOID(self, implied: bool = False) -> Iterable[int]:
        if not implied:
            yield len(self.data)

        yield from self.data

    @classmethod
    def fromOID(
        cls: Type[TOCTET_STRING],
        nums: Iterator[int],
        implied: bool = False,
    ) -> TOCTET_STRING:
        if implied:
            data = bytes(nums)
        else:
            length = next(nums)
            data = bytes([next(nums) for _ in range(length)])

        try:
            return cls.construct(data)
        except ParseError as err:
            raise OBJECT_IDENTIFIER.IndexDecodeError(*err.args) from err

    @classmethod
    def construct(cls: Type[TOCTET_STRING], data: Asn1Data) -> TOCTET_STRING:
        if isinstance(data, subbytes):
            data = data[:]

        return cls(data)

    @classmethod
    def deserialize(cls: Type[TOCTET_STRING], data: Asn1Data) -> TOCTET_STRING:
        return cls.construct(data)

    def serialize(self) -> bytes:
        return self.data

class NULL(Primitive):
    TAG = Tag(5)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, NULL):
            return NotImplemented

        return self.TAG == other.TAG

    def __repr__(self) -> str:
        return f"{typename(self)}()"

    def asOID(self, implied: bool = False) -> Iterable[int]:
        return ()

    @classmethod
    def fromOID(
        cls: Type[TNULL],
        nums: Iterator[int],
        implied: bool = False,
    ) -> TNULL:
        return cls()

    @classmethod
    def deserialize(cls: Type[TNULL], data: Asn1Data) -> TNULL:
        return cls()

    def serialize(self) -> bytes:
        return b""

class OBJECT_IDENTIFIER(Primitive):
    TAG = Tag(6)

    class BadPrefix(SNMPException):
        pass

    class IndexDecodeError(SNMPException):
        pass

    def __init__(self, *subidentifiers: int) -> None:
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

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, OBJECT_IDENTIFIER):
            return NotImplemented

        return self.subidentifiers == other.subidentifiers

    def __lt__(self, other: "OBJECT_IDENTIFIER") -> bool:
        return self.subidentifiers < other.subidentifiers

    @overload
    def __getitem__(self, index: int) -> int:
        ...

    @overload
    def __getitem__(self, index: slice) -> Tuple[int, ...]:
        ...

    def __getitem__(self,
        index: Union[int, slice],
    ) -> Union[int, Tuple[int, ...]]:
        return self.subidentifiers.__getitem__(index)

    def __hash__(self) -> int:
        return self.subidentifiers.__hash__()

    def __iter__(self) -> Iterator[int]:
        return iter(self.subidentifiers)

    def __len__(self) -> int:
        return len(self.subidentifiers)

    def __repr__(self) -> str:
        args = ", ".join(str(i) for i in self.subidentifiers)
        return f"{typename(self)}({args})"

    def __str__(self) -> str:
        return ".".join(str(i) for i in  self.subidentifiers)

    @classmethod
    def parse(cls: Type[TOID], oid: str) -> TOID:
        numbers = oid.split(".")

        if numbers[0] == "":
            numbers = numbers[1:]

        try:
            return cls(*(int(n) for n in numbers))
        except ValueError as err:
            raise ValueError(f"Invalid {typename(cls)} string: {oid}") from err

    def asOID(self, implied: bool = False) -> Iterable[int]:
        if not implied:
            yield len(self.subidentifiers)

        yield from self.subidentifiers

    @classmethod
    def fromOID(
        cls: Type[TOID],
        nums: Iterator[int],
        implied: bool = False,
    ) -> TOID:
        if implied:
            subidentifiers = nums
        else:
            length = next(nums)
            subidentifiers = (next(nums) for _ in range(length))

        try:
            return cls.construct(*subidentifiers)
        except ParseError as err:
            raise OBJECT_IDENTIFIER.IndexDecodeError(*err.args) from err

    def extend(self: TOID, *subidentifiers: int) -> TOID:
        return self.__class__(*self.subidentifiers, *subidentifiers)

    def startswith(self, prefix: "OBJECT_IDENTIFIER") -> bool:
        return self.subidentifiers[:len(prefix)] == prefix[:]

    def decodeIndex(self: TOID,
        prefix: TOID,
        *types: Type[TPrimitive],
        implied: bool = False,
    ) -> Tuple[TPrimitive, ...]:
        if not self.startswith(prefix):
            raise self.BadPrefix(f"{self} does not begin with {prefix}")

        nums = iter(self.subidentifiers[len(prefix):])

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
            errmsg = "Not all sub-identifiers were consumed"
            raise self.IndexDecodeError(errmsg)

        return tuple(index)

    @staticmethod
    def decodeIndexField(
        nums: Iterator[int],
        cls: Type[TPrimitive],
        implied: bool = False,
    ) -> TPrimitive:
        try:
            return cls.fromOID(nums, implied=implied)
        except StopIteration as err:
            errmsg = f"Incomplete {typename(cls)} field in index"
            raise OBJECT_IDENTIFIER.IndexDecodeError(errmsg)

    def withIndex(self: TOID,
        *index: Primitive,
        implied: bool = False,
    ) -> TOID:
        oid = self

        for obj in index[:-1]:
            oid = oid.extend(*obj.asOID())

        for obj in index[-1:]:
            oid = oid.extend(*obj.asOID(implied=implied))

        return oid

    @classmethod
    def construct(cls: Type[TOID], *subidentifiers: int) -> TOID:
        try:
            return cls(*subidentifiers)
        except ValueError as err:
            raise ParseError(*err.args) from err

    @classmethod
    def deserialize(cls: Type[TOID], data: Asn1Data) -> TOID:
        stream = iter(data)

        try:
            oid = list(divmod(next(stream), 40))
        except StopIteration as err:
            raise ParseError(f"Empty {typename(cls)}") from err

        value = 0
        for byte in stream:
            value |= byte & 0x7f
            if byte & 0x80:
                value <<= 7
            else:
                oid.append(value)
                value = 0

        if value:
            raise ParseError(f"{typename(cls)} ended unexpectedly")

        return cls.construct(*oid)

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

    def serialize(self) -> bytes:
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
