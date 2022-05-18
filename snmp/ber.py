__all__ = [
    "EncodeError", "ParseError",
    "CLASS_UNIVERSAL", "CLASS_APPLICATION",
    "CLASS_CONTEXT_SPECIFIC", "CLASS_PRIVATE",
    "STRUCTURE_PRIMITIVE", "STRUCTURE_CONSTRUCTED",
    "Identifier", "decode", "encode",
]

from collections import namedtuple
from .exception import *
from .utils import subbytes

class EncodeError(SNMPException):
    pass

class ParseError(IncomingMessageError):
    pass

CLASS_UNIVERSAL         = 0
CLASS_APPLICATION       = 1
CLASS_CONTEXT_SPECIFIC  = 2
CLASS_PRIVATE           = 3

STRUCTURE_PRIMITIVE     = 0
STRUCTURE_CONSTRUCTED   = 1

Identifier = namedtuple("Identifier", ("cls", "structure", "tag"))

def decode_identifier(data):
    try:
        byte = data.consume()
    except IndexError as err:
        raise ParseError("Missing identifier") from err

    cls         = (byte & 0xc0) >> 6
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

    return Identifier(cls, structure, tag)

def encode_identifier(i):
    byte = (
        ((i.cls       << 6) & 0xc0) |
        ((i.structure << 5) & 0x20)
    )

    arr = bytearray()
    if i.tag < 0x1f:
        byte |= i.tag
    else:
        byte |= 0x1f

        tag = i.tag
        indicator = 0
        while tag:
            arr.append(indicator | (tag & 0x7f))
            indicator = 0x80
            tag >>= 7

    arr.append(byte)
    return bytes(reversed(arr))

def decode_length(data):
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

def encode_length(length):
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

def decode(data, expected=None, leftovers=False, copy=True):
    data = subbytes(data)
    identifier = decode_identifier(data)

    result = []
    if expected is None:
        result.append(identifier)
    elif identifier != expected:
        raise ParseError("Identifier does not match expected type")

    length = decode_length(data)
    pruned = data.prune(length)

    if len(data) < length:
        raise ParseError("Incomplete value")

    if copy:
        result.append(data[:])
    else:
        result.append(data)

    if leftovers:
        result.append(pruned)
    elif pruned:
        raise ParseError("Trailing bytes")

    if len(result) == 1:
        return result[0]
    else:
        return tuple(result)

def encode(identifier, data):
    return encode_identifier(identifier) + encode_length(len(data)) + data
