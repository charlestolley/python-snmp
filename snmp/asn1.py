__all__ = ["ASN1Type","ASN1Primitive", "INTEGER"]

from abc import abstractmethod
from snmp.ber import *
from snmp.typing import *
from snmp.utils import *

ASN1TypeVar = TypeVar("ASN1TypeVar",    bound="ASN1Type")
TINTEGER    = TypeVar("TINTEGER",       bound="INTEGER")

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
    def deserialize(cls: Type[TINTEGER], data: Asn1Data) -> TINTEGER:
        value = int.from_bytes(data, cls.BYTEORDER, signed=True)
        return cls(value)

    def serialize(self) -> bytes:
        # equivalent to (N + 8) // 8
        # the reason it's not (N + 7) is that ASN.1 always includes a sign bit
        nbytes = (self.bitCount(self.value) // 8) + 1
        return self.value.to_bytes(nbytes, self.BYTEORDER, signed=True)
