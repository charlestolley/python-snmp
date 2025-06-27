__all__ = ["Asn1Data", "Tag", "decode", "decodeExact", "encode"]

from enum import IntEnum

from snmp.exception import *
from snmp.typing import *
from snmp.utils import *

Asn1Data = Union[bytes, subbytes]

class EnhancedParseError(ParseError):
    def __init__(self, msg: str, data: subbytes):
        super().__init__(msg)
        self.data = data

@final
class Tag:
    """Represents an ASN.1 BER tag."""
    @final
    class Class(IntEnum):
        """Named constants for the class bits of an ASN.1 BER tag."""
        UNIVERSAL         = 0
        APPLICATION       = 1
        CONTEXT_SPECIFIC  = 2
        PRIVATE           = 3

    def __init__(self,
        number: int,
        constructed: bool = False,
        cls: Class = Class.UNIVERSAL,
    ) -> None:
        self.cls = cls
        self.constructed = constructed
        self.number = number

    def __eq__(self, other: Any) -> bool:
        if other.__class__ != self.__class__:
            return NotImplemented

        return (    # type: ignore[no-any-return]
            self.cls == other.cls
        and self.constructed == other.constructed
        and self.number == other.number
        )

    def __hash__(self) -> int:
        return hash((self.cls, self.constructed, self.number))

    def __repr__(self) -> str:
        return f"Tag({self.number}, {self.constructed}, {self.cls})"

    @classmethod
    def decode(cls, data: subbytes) -> Tuple["Tag", subbytes]:
        """Extract the tag from an ASN.1 BER string.

        This function decodes the tag portion of a BER string an returns it as
        a Tag object. It also returns a subbytes of the data argument
        referencing everything after the tag.
        """
        try:
            byte, ptr = data.pop_front()
        except IndexError as err:
            raise EnhancedParseError("Missing tag", data) from err

        class_      = (byte & 0xc0) >> 6
        constructed = (byte & 0x20) != 0
        number      = (byte & 0x1f)

        if number == 0x1f:
            number = 0
            byte = 0x80
            while byte & 0x80:
                try:
                    byte, ptr = ptr.pop_front()
                except IndexError as err:
                    raise EnhancedParseError("Incomplete tag", data) from err

                number <<= 7
                number |= byte & 0x7f

        return cls(number, constructed, cls.Class(class_)), ptr

    def encode(self) -> bytes:
        """Encode a Tag under ASN.1 Basic Encoding Rules."""
        byte = (self.cls << 6) & 0xc0

        if self.constructed:
            byte |= 0x20

        arr = bytearray()
        if self.number < 0x1f:
            byte |= self.number
        else:
            byte |= 0x1f

            number = self.number
            indicator = 0
            while number:
                arr.append(indicator | (number & 0x7f))
                indicator = 0x80
                number >>= 7

        arr.append(byte)
        return bytes(reversed(arr))

def decode_length(data: subbytes) -> Tuple[int, subbytes]:
    """Decode the length field of an ASN.1 BER string.

    The provided data argument should contain most of a BER string, starting
    after the tag. This function will decode the length field and return it as
    an int, along with a new subbytes object referencing to the portion of the
    data argument immediately following the length field.
    """
    try:
        length, ptr = data.pop_front()
    except IndexError as err:
        raise EnhancedParseError("Missing length", data) from err

    if length & 0x80:
        n = length & 0x7f

        length = 0
        for i in range(n):
            try:
                byte, ptr = ptr.pop_front()
            except IndexError as err:
                raise EnhancedParseError("Incomplete length", data) from err

            length <<= 8
            length |= byte

    return length, ptr

def encode_length(length: int) -> bytes:
    """Encode the length of a message under ASN.1 Basic Encoding Rules."""
    if length < 0x80:
        return bytes([length])

    arr = bytearray()
    while length:
        arr.append(length & 0xff)
        length >>= 8

    if len(arr) > 0x7f:
        raise EncodeError("Length too large for definite-length encoding")

    arr.append(0x80 | len(arr))
    return bytes(reversed(arr))

def decode(data: Union[bytes, subbytes]) -> Tuple[Tag, subbytes, subbytes]:
    original = subbytes(data)
    tag, ptr = Tag.decode(original)
    length, ptr = decode_length(ptr)

    if len(ptr) < length:
        raise EnhancedParseError("Incomplete value", original)

    body, tail = ptr.split(length)
    return tag, body, tail

def decodeExact(data: Union[bytes, subbytes]) -> Tuple[Tag, subbytes]:
    tag, body, tail = decode(data)

    if tail:
        raise EnhancedParseError(f"Trailing bytes", tail)

    return tag, body

def encode(tag: Tag, data: bytes) -> bytes:
    """Encode a message under ASN.1 Basic Encoding Rules."""
    return tag.encode() + encode_length(len(data)) + data
