__all__ = [
    'ASN1', 'INTEGER', 'OCTET_STRING', 'NULL', 'OID', 'SEQUENCE', 'UNSIGNED',
    'Counter32', 'Gauge32', 'TimeTicks', 'Integer32', 'Counter64', 'IpAddress',
    'VarBind', 'VarBindList', 'PDU', 'GetRequestPDU', 'GetNextRequestPDU',
    'GetResponsePDU', 'SetRequestPDU', 'Message',
]

from copy import copy
import socket

from .exceptions import EncodingError, ProtocolError

def unpack(obj):
    if len(obj) < 2:
        raise EncodingError("object encoding is too short")

    dtype = obj[0]
    l = obj[1]

    index = 2
    if l & 0x80:
        index += l & 0x7f

        if len(obj) < index:
            raise EncodingError("Long form length field is incomplete")

        l = 0
        for num in obj[2:index]:
            l <<= 8
            l += num

    if len(obj) < index + l:
        raise EncodingError("Invalid length field: object encoding too short")

    return dtype, obj[index:index+l], obj[index+l:]

def length(l):
    if l < 0x80:
        return bytes([l])

    bytearr = bytearray()
    while l:
        bytearr.append(l & 0xff)
        l >>= 8

    # this works as long as (l < 2^1008), which is super big
    bytearr.append(len(bytearr) | 0x80)

    return bytes(reversed(bytearr))

class ASN1:
    def __init__(self, value=None, encoding=None):
        self._encoding = encoding
        self._value = value

    def __repr__(self):
        return "{}({})".format(self.__class__.__name__, self)

    @classmethod
    def copy(cls, obj):
        return cls(encoding=obj.encoding)

    @staticmethod
    def deserialize(obj, cls=None, leftovers=False):
        dtype, encoding, tail = unpack(obj)
        if tail and not leftovers:
            raise EncodingError("Unexpected trailing bytes")

        if cls is None:
            try:
                cls = types[dtype]
            except KeyError as e:
                message = "Unknown type: '0x{:02x}'".format(dtype)
                raise ProtocolError(message) from e

        elif dtype != cls.TYPE:
            message = "Expected type '0x{:02x}'; got '0x{:02x}'"
            message = message.format(cls.TYPE, dtype)
            raise ProtocolError(message)

        obj = cls(encoding=encoding)

        return (obj, tail) if leftovers else obj

    def serialize(self):
        return bytes([self.TYPE]) + length(len(self.encoding)) + self.encoding

    # The following methods must be overwritten for sequence types
    def __bool__(self):
        return bool(self.value)

    def __eq__(self, other):
        return self.value == other

    def __ge__(self, other):
        return self.value >= other

    def __gt__(self, other):
        return self.value > other

    def __le__(self, other):
        return self.value <= other

    def __lt__(self, other):
        return self.value < other

    def __ne__(self, other):
        return self.value != other

    def __str__(self):
        return repr(self.value)

    def poke(self):
        self.value

### Primitive types ###

class INTEGER(ASN1):
    SIGNED = True

    @property
    def encoding(self):
        if self._encoding is None:
            encoding = bytearray()
            x = self._value

            # do - while
            while True:
                encoding.append(x & 0xff)
                x >>= 8
                if x in (0, -1):
                    break

            self._encoding = bytes(reversed(encoding))
        return self._encoding

    @property
    def value(self):
        if self._value is None:
            negative = self.SIGNED and bool(self._encoding[0] & 0x80)

            x = 0
            for byte in self._encoding:
                x <<= 8
                x |= byte

            if negative:
                bits = 8 * len(self._encoding)
                self._value = -(~x + (1 << bits) + 1)
            else:
                self._value = x

        return self._value

class OCTET_STRING(ASN1):
    @property
    def encoding(self):
        if self._encoding is None:
            self._encoding = self._value
        return self._encoding

    @property
    def value(self):
        if self._value is None:
            self._value = self._encoding
        return self._value

class NULL(ASN1):
    def __init__(self, value=None, encoding=None):
        if encoding:
            raise EncodingError("Non-null encoding for NULL type")
        elif value is not None:
            raise ValueError("NULL cannot have non-null value")

    def __str__(self):
        return ""

    @property
    def encoding(self):
        return b''

    @property
    def value(self):
        return None

class OID(ASN1):
    @property
    def encoding(self):
        if self._encoding is None:
            if self._value[0] == '.':
                self._value = self.value[1:]

            segments = [int(segment) for segment in self._value.split('.')]

            if len(segments) > 1:
                segments[1] += segments[0] * 40
                segments = segments[1:]

            encoding = bytearray()
            for num in segments:
                bytearr = bytearray()
                while num > 0x7f:
                    bytearr.append(num & 0x7f)
                    num >>= 7
                bytearr.append(num)

                for i in range(1, len(bytearr)):
                    bytearr[i] |= 0x80

                bytearr.reverse()
                encoding += bytearr

            self._encoding = bytes(encoding)

        return self._encoding

    @property
    def value(self):
        if self._value is None:
            encoding = self._encoding

            first = encoding[0]
            oid = [str(num) for num in divmod(first, 40)]

            val = 0
            for byte in encoding[1:]:
                val |= byte & 0x7f
                if byte & 0x80:
                    val <<= 7
                else:
                    oid.append(str(val))
                    val = 0

            if val:
                raise EncodingError("OID ended in a byte with bit 7 set")

            self._value = '.'.join(oid)

        return self._value

class SEQUENCE(ASN1):
    EXPECTED = None

    def __init__(self, *values, encoding=None):
        self.expected = copy(self.EXPECTED)

        self._encoding = encoding
        self._values = values or None

    def __bool__(self):
        return bool(self.values)

    def __eq__(self, other):
        return self.values == other

    def __ge__(self, other):
        return self.values >= other

    def __gt__(self, other):
        return self.values > other

    def __le__(self, other):
        return self.values <= other

    def __lt__(self, other):
        return self.values < other

    def __ne__(self, other):
        return self.values != other

    def __str__(self):
        return repr(self)

    def __repr__(self, depth=0):
        string = "{}{}:\n".format('\t'*depth, self.__class__.__name__)
        depth += 1
        for entry in self.values:
            if isinstance(entry, SEQUENCE):
                string += entry.__repr__(depth=depth)
            else:
                string += "{}{}: {}\n".format(
                    '\t'*depth,
                    entry.__class__.__name__,
                    entry
                )

        return string

    def poke(self):
        for val in self.values:
            val.poke()

    @property
    def encoding(self):
        if self._encoding is None:
            encodings = [None] * len(self.values)
            for i in range(len(self.values)):
                encodings[i] = self.values[i].serialize()

            self._encoding = b''.join(encodings)

        return self._encoding

    @property
    def values(self):
        if self._values is None:
            definite = isinstance(self.expected, list)

            sequence = []
            encoding = self._encoding
            while encoding:
                if definite:
                    try:
                        cls = self.expected[len(sequence)]
                    except IndexError as e:
                        message = "{} has too many elements"
                        message = message.format(self.__class__.__name__)
                        raise ProtocolError(message) from e
                else:
                    cls = self.expected

                obj, encoding = ASN1.deserialize(encoding, cls=cls, leftovers=True)
                sequence.append(obj)

            if definite and len(sequence) < len(self.expected):
                message = "{} has too few elements"
                message = message.format(self.__class__.__name__)
                raise ProtocolError(message)

            self._values = tuple(sequence)

        return self._values

### Composed types ###

class UNSIGNED(INTEGER):
    SIGNED = False

class Counter32(UNSIGNED):
    pass

class Gauge32(UNSIGNED):
    pass

class TimeTicks(UNSIGNED):
    pass

class Integer32(INTEGER):
    pass

class Counter64(UNSIGNED):
    pass

class IpAddress(OCTET_STRING):
    @property
    def encoding(self):
        if self._encoding is None:
            self._encoding = socket.inet_aton(self._value)
        return self._encoding

    @property
    def value(self):
        if self._value is None:
            if len(self._encoding) == 4:
                self._value = socket.inet_ntoa(self._encoding)
            else:
                raise ProtocolError("IP Address must be 4 bytes long")
        return self._value

class VarBind(SEQUENCE):
    EXPECTED = [
        OID,
        None,
    ]

    def __init__(self, *args, **kwargs):
        super(VarBind, self).__init__(*args, **kwargs)
        self.error = None

    @property
    def name(self):
        return self.values[0]

    @property
    def value(self):
        return self.values[1]

class VarBindList(SEQUENCE):
    EXPECTED = VarBind

    def __getitem__(self, index):
        return self.values[index]

    def __iter__(self):
        return iter(self.values)

    def __len__(self):
        return len(self.values)

class PDU(SEQUENCE):
    EXPECTED = [
        INTEGER,
        INTEGER,
        INTEGER,
        VarBindList,
    ]

    def __init__(self, request_id=0, error_status=0, error_index=0, vars=None, encoding=None):
        values = (
            INTEGER.copy(UNSIGNED(request_id)),
            INTEGER(error_status),
            INTEGER(error_index),
            vars,
        ) if encoding is None else ()
        super(PDU, self).__init__(*values, encoding=encoding)

    @property
    def request_id(self):
        return self.values[0]

    @property
    def error_status(self):
        return self.values[1]

    @property
    def error_index(self):
        return self.values[2]

    @property
    def vars(self):
        return self.values[3]

class GetRequestPDU(PDU):
    pass

class GetNextRequestPDU(PDU):
    pass

class GetResponsePDU(PDU):
    pass

class SetRequestPDU(PDU):
    pass

class Message(SEQUENCE):
    EXPECTED = [
        INTEGER,
        OCTET_STRING,
        GetResponsePDU,
    ]

    def __init__(self, version=0, community=b'public', data=None, encoding=None):
        values = (
            INTEGER(version),
            OCTET_STRING(community),
            data,
        ) if encoding is None else ()
        super(Message, self).__init__(*values, encoding=encoding)

    @property
    def version(self):
        return self.values[0]

    @property
    def community(self):
        return self.values[1]

    @property
    def data(self):
        return self.values[2]

types = {
    0x02: INTEGER,
    0x04: OCTET_STRING,
    0x05: NULL,
    0x06: OID,
    0x30: SEQUENCE,
    0x40: IpAddress,
    0x41: Counter32,
    0x42: Gauge32,
    0x43: TimeTicks,
    0x44: Integer32,
    0x46: Counter64,
    0xa0: GetRequestPDU,
    0xa1: GetNextRequestPDU,
    0xa2: GetResponsePDU,
    0xa3: SetRequestPDU,
}

for dtype, cls in types.items():
    cls.TYPE = dtype
