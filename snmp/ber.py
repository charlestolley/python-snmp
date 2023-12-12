__all__ = ["EncodeError", "ParseError", "Asn1Data", "Tag", "decode", "encode"]

from enum import IntEnum

from snmp.exception import *
from snmp.typing import *
from snmp.utils import *

Asn1Data = Union[bytes, subbytes]

@final
class EncodeError(SNMPException):
    """Failure to encode a payload under ASN.1 Basic Encoding Rules."""
    pass

@final
class ParseError(IncomingMessageError):
    """Failure to translate a byte string into an ASN.1 object."""
    pass

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
            byte = data.dereference()
        except IndexError as err:
            raise ParseError("Missing tag") from err
        else:
            data = data.advance()

        class_      = (byte & 0xc0) >> 6
        constructed = (byte & 0x20) != 0
        number      = (byte & 0x1f)

        if number == 0x1f:
            number = 0
            byte = 0x80
            while byte & 0x80:
                try:
                    byte = data.dereference()
                except IndexError as err:
                    raise ParseError("Incomplete tag") from err
                else:
                    data = data.advance()

                number <<= 7
                number |= byte & 0x7f

        return cls(number, constructed, cls.Class(class_)), data

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
        length = data.dereference()
    except IndexError as err:
        raise ParseError("Missing length") from err
    else:
        data = data.advance()

    if length & 0x80:
        n = length & 0x7f

        length = 0
        for i in range(n):
            try:
                byte = data.dereference()
            except IndexError as err:
                raise ParseError("Incomplete length") from err
            else:
                data = data.advance()

            length <<= 8
            length |= byte

    return length, data

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

def decode( # type: ignore[no-untyped-def]
    data: Asn1Data,
    expected: Optional[Tag] = None,
    leftovers: bool = False,
    copy: bool = True,
):
    """Extract the contents of an ASN.1 BER string.

    This function has several options for what it can return depending on the
    values of its arguments. In the default case, given only the data argument,
    it will return a tuple, where the first element is the Tag, and the second
    contains the body of the message as a bytes object. In this case, the
    function expects to consume the entire message, and will raise a ParseError
    if it contains more bytes than what the length field indicates. A value of
    True for the leftovers argument will change this behavior, so that it will
    return the leftover data in a snmp.utils.subbytes object as an additional
    element of the returned tuple.

    The expected argument allows the caller to provide a Tag, telling the
    function what data type is expected. In this case, the body will be
    returned without the tag, and the return value will not use a tuple (unless
    leftovers was given as True). If the decoded object does not match the
    expected type, the function will raise a ParseError.

    The copy argument allows the caller to specify whether the body of the
    message should be copied into its own bytes object (the default), or use a
    snmp.utils.subbytes object, in order to preserve a reference to the complete
    message.
    """
    data = subbytes(data)
    tag, data = Tag.decode(data)

    if expected is not None and tag != expected:
        raise ParseError("Tag does not match expected type")

    length, data = decode_length(data)
    data, tail = data.split(length)

    if len(data) < length:
        raise ParseError("Incomplete value")
    elif not leftovers and tail:
        raise ParseError("Trailing bytes")

    body = data[:] if copy else data

    if expected is None:
        if leftovers:
            return tag, body, tail
        else:
            return tag, body
    else:
        if leftovers:
            return body, tail
        else:
            return body

def encode(tag: Tag, data: bytes) -> bytes:
    """Encode a message under ASN.1 Basic Encoding Rules."""
    return tag.encode() + encode_length(len(data)) + data
