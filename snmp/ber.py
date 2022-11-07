__all__ = [
    "EncodeError", "ParseError",
    "Class", "Structure", "Identifier",
    "decode_identifier", "decode", "encode",
]

from enum import IntEnum

from snmp.exception import *
from snmp.typing import *
from snmp.utils import subbytes

class EncodeError(SNMPException):
    pass

class ParseError(IncomingMessageError):
    pass

class Class(IntEnum):
    UNIVERSAL         = 0
    APPLICATION       = 1
    CONTEXT_SPECIFIC  = 2
    PRIVATE           = 3

class Structure(IntEnum):
    PRIMITIVE     = 0
    CONSTRUCTED   = 1

class Identifier(NamedTuple):
    cls: Class
    structure: Structure
    tag: int

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

def encode(identifier, data):
    return encode_identifier(identifier) + encode_length(len(data)) + data
