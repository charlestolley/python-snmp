__all__ = ["ASN1Type","ASN1Primitive", "INTEGER", "OCTET_STRING"]

from abc import abstractmethod
from snmp.ber import *
from snmp.typing import *
from snmp.utils import *

ASN1TypeVar     = TypeVar("ASN1TypeVar",    bound="ASN1Type")
TINTEGER        = TypeVar("TINTEGER",       bound="INTEGER")
TOCTET_STRING   = TypeVar("TOCTET_STRING",  bound="OCTET_STRING")

class ASN1Type:
    TAG: ClassVar[Tag]

    @classmethod
    def decode(
        cls: Type[ASN1TypeVar],
        data: Asn1Data,
        leftovers: bool = False,
        copy: bool = True,
        **kwargs: Any,
    ) -> Union[ASN1TypeVar, Tuple[ASN1TypeVar, subbytes]]:
        if leftovers:
            encoding, tail = decode(data, cls.TAG, True, copy)
            return cls.deserialize(encoding, **kwargs), tail
        else:
            encoding = decode(data, cls.TAG, False, copy)
            return cls.deserialize(encoding, **kwargs)

    def encode(self) -> bytes:
        return encode(self.TAG, self.serialize())

    @classmethod
    @abstractmethod
    def deserialize(cls: Type[ASN1TypeVar], data: Asn1Data) -> ASN1TypeVar:
        ...

    @abstractmethod
    def serialize(self) -> bytes:
        ...

class ASN1Primitive(ASN1Type):
    pass

class INTEGER(ASN1Primitive):
    BYTEORDER: ClassVar[str] = "big"
    TAG = Tag(2)

    def __init__(self, value: int) -> None:
        self._value = value

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, INTEGER):
            return NotImplemented

        return self.value == other.value

    def __repr__(self) -> str:
        return f"{typename(self)}({self.value})"

    @property
    def value(self) -> int:
        return self._value

    @staticmethod
    def bitCount(value) -> int:
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

    # TODO: These methods are hacked in from the old Integer.
    #       They will need some tweaks once the new OID type is in place.
    def appendToOID(self, oid, implied: bool = False):
        return oid.extend(self.value)

    @classmethod
    def decodeFromOID(
        cls,
        nums: Iterator[int],
        implied: bool = False,
    ):
        value = next(nums)

        if not cls.inRange(value):
            errmsg = f"{typename(cls)} value out of range: {value}"
            raise OID.IndexDecodeError(errmsg)

        return cls(value)

class OCTET_STRING(ASN1Primitive):
    TAG = Tag(4)

    def __init__(self, data: bytes = b"") -> None:
        self._data = data

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, OCTET_STRING):
            return NotImplemented

        return self.data == other.data

    def __repr__(self) -> str:
        return f"{typename(self)}({repr(self.data)})"

    @property
    def data(self) -> bytes:
        return self._data

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
