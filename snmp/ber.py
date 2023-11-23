__all__ = [
    "EncodeError", "ParseError",
    "Asn1Data", "Class", "Structure", "Identifier",
    "decode", "encode",
]

from enum import IntEnum

from snmp.exception import *
from snmp.typing import *
from snmp.utils import subbytes

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
class Class(IntEnum):
    """Named constants for the class bits of an ASN.1 BER identifier."""
    UNIVERSAL         = 0
    APPLICATION       = 1
    CONTEXT_SPECIFIC  = 2
    PRIVATE           = 3

@final
class Structure(IntEnum):
    """Named constants for the constructed bit of an ASN.1 BER identifier."""
    PRIMITIVE     = 0
    CONSTRUCTED   = 1

TIdentifier = TypeVar("TIdentifier", bound="Identifier")

@final
class Identifier(NamedTuple):
    """Represents an ASN.1 BER identifier."""
    cls: Class
    structure: Structure
    tag: int

    @classmethod
    def decode(cls: Type[TIdentifier], data: subbytes) -> TIdentifier:
        """Extract the identifier from an ASN.1 BER string.

        This function decodes the identifier portion of a BER string an returns
        it as an :class:`Identifier` object. As a side-effect, it advances the
        start of the `data` argument to point to the byte immediately after the
        identifier.
        """
        try:
            byte = data.consume()
        except IndexError as err:
            raise ParseError("Missing identifier") from err

        class_      = (byte & 0xc0) >> 6
        structure   = (byte & 0x20) >> 5
        tag         = (byte & 0x1f)

        if tag == 0x1f:
            tag = 0
            byte = 0x80
            while byte & 0x80:
                try:
                    byte = data.consume()
                except IndexError as err:
                    raise ParseError("Incomplete identifier") from err

                tag <<= 7
                tag |= byte & 0x7f

        return cls(Class(class_), Structure(structure), tag)

    def encode(self) -> bytes:
        """Encode an Identifier under ASN.1 Basic Encoding Rules."""
        byte = (
            ((self.cls       << 6) & 0xc0) |
            ((self.structure << 5) & 0x20)
        )

        arr = bytearray()
        if self.tag < 0x1f:
            byte |= self.tag
        else:
            byte |= 0x1f

            tag = self.tag
            indicator = 0
            while tag:
                arr.append(indicator | (tag & 0x7f))
                indicator = 0x80
                tag >>= 7

        arr.append(byte)
        return bytes(reversed(arr))

def decode_length(data: subbytes) -> int:
    """Decode the length field of an ASN.1 BER string.

    The provided `data` argument should contain most of a BER string,
    starting after the identifier. The most natural way to use it is to pass
    the same object first to :func:`Identifier.decode` and then to
    :func:`decode_length`. This function will decode the length field and
    return it as an :class:`int`, modifying the `data` argument to start
    immediately after the length field.
    """
    try:
        length = data.consume()
    except IndexError as err:
        raise ParseError("Missing length") from err

    if length & 0x80:
        n = length & 0x7f

        length = 0
        for i in range(n):
            try:
                byte = data.consume()
            except IndexError as err:
                raise ParseError("Incomplete length") from err

            length <<= 8
            length |= byte

    return length

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

@overload
def decode(
    data: Asn1Data,
    expected: None,
    leftovers: Literal[False],
    copy: Literal[False],
) -> Tuple[Identifier, subbytes]:
    ...

@overload
def decode(
    data: Asn1Data,
    expected: None = None,
    leftovers: Literal[False] = False,
    copy: Literal[True] = True,
) -> Tuple[Identifier, bytes]:
    ...

@overload
def decode(
    data: Asn1Data,
    expected: None,
    leftovers: Literal[True],
    copy: Literal[False],
) -> Tuple[Identifier, subbytes, subbytes]:
    ...

@overload
def decode(
    data: Asn1Data,
    expected: None,
    leftovers: Literal[True],
    copy: Literal[True] = True,
) -> Tuple[Identifier, bytes, subbytes]:
    ...

@overload
def decode(
    data: Asn1Data,
    expected: Identifier,
    leftovers: Literal[False],
    copy: Literal[False],
) -> subbytes:
    ...

@overload
def decode(
    data: Asn1Data,
    expected: Identifier,
    leftovers: Literal[False] = False,
    copy: Literal[True] = True,
) -> bytes:
    ...

@overload
def decode(
    data: Asn1Data,
    expected: Identifier,
    leftovers: Literal[True],
    copy: Literal[False],
) -> Tuple[subbytes, subbytes]:
    ...

@overload
def decode(
    data: Asn1Data,
    expected: Identifier,
    leftovers: Literal[True],
    copy: Literal[True] = True,
) -> Tuple[bytes, subbytes]:
    ...

def decode( # type: ignore[no-untyped-def]
    data: Asn1Data,
    expected: Optional[Identifier] = None,
    leftovers: bool = False,
    copy: bool = True,
):
    """Extract the contents of an ASN.1 BER string.

    This function has several options for what it can return depending on
    the values of its arguments. In the default case, given only the `data`
    argument, it will return a tuple, where the first element is the
    :class:`Identifier`, and the second contains the body of the message as
    a `bytes` object. In this case, the function expects to consume the
    entire message, and will raise a :class:`ParseError` if it contains more
    bytes than what the length field indicates. A value of ``True`` for the
    `leftovers` argument will change this behavior, so that it will return
    the leftover data in a :class:`snmp.utils.subbytes` object as an
    additional element of the returned tuple.

    The `expected` argument allows the caller to provide an
    :class:`Identifier`, telling the function what data type is expected. In
    this case, the body will be returned without the identifier, and the
    return value will not use a tuple (unless `leftovers` was given as
    ``True``). If the decoded object does not match the expected type, the
    function will raise a :class:`ParseError`.

    The `copy` argument allows the caller to specify whether the body of the
    message should be copied into its own :class:`bytes` object (the
    default), or use a :class:`snmp.utils.subbytes` object, in order to
    preserve a reference to the complete message.
    """
    data = subbytes(data)
    identifier = Identifier.decode(data)

    if expected is not None and identifier != expected:
        raise ParseError("Identifier does not match expected type")

    length = decode_length(data)
    tail = data.prune(length)

    if len(data) < length:
        raise ParseError("Incomplete value")
    elif not leftovers and tail:
        raise ParseError("Trailing bytes")

    body = data[:] if copy else data

    if expected is None:
        if leftovers:
            return identifier, body, tail
        else:
            return identifier, body
    else:
        if leftovers:
            return body, tail
        else:
            return body

def encode(identifier: Identifier, data: bytes) -> bytes:
    """Encode a message under ASN.1 Basic Encoding Rules."""
    return identifier.encode() + encode_length(len(data)) + data
