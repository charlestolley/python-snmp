from copy import copy
from .exceptions import EncodingError, ProtocolError

def decode(obj):
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

def encode_length(l):
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

    def __str__(self):
        return repr(self.value)

    @classmethod
    def copy(cls, obj):
        return cls(encoding=obj.encoding)

    @staticmethod
    def deserialize(obj, cls=None):
        dtype, encoding, tail = decode(obj)
        if cls is None:
            try:
                cls = types[dtype]
            except KeyError as e:
                message = "Unknown type: '0x{:02x}'".format(dtype)
                raise EncodingError(message) from e

        elif dtype != cls.TYPE:
            message = "Expected type '0x{:02x}'; got '0x{:02x}'"
            message = message.format(cls.TYPE, dtype)
            raise ProtocolError(message)

        return cls(encoding=encoding), tail

    def serialize(self):
        l = len(self.encoding)
        return bytes([self.TYPE]) + encode_length(l) + self.encoding

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
                if (x == 0 or ~x == 0):
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
    def __init__(self, value=None, encoding=None):
        if value is None:
            value = encoding

        if isinstance(value, str):
            value = value.encode()

        self.encoding = value
        self.value = value

class OID(ASN1):
    @property
    def encoding(self):
        if self._encoding is None:
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
            for i in range(1, len(encoding)):
                byte = encoding[i]
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

    def __init__(self, *value, encoding=None):
        self.expected = copy(self.EXPECTED)

        self._encoding = encoding
        self._value = value or None

    def __repr__(self, depth=0):
        string = "{}{}:\n".format('\t'*depth, self.__class__.__name__)
        depth += 1
        for entry in self.value:
            if isinstance(entry, SEQUENCE):
                string += entry.__repr__(depth=depth)
            else:
                string += "{}{}: {}\n".format(
                    '\t'*depth,
                    entry.__class__.__name__,
                    entry
                )

        return string

    @property
    def encoding(self):
        if self._encoding is None:
            encodings = [None] * len(self.value)
            for i in range(len(self.value)):
                encodings[i] = self.value[i].serialize()

            self._encoding = b''.join(encodings)

        return self._encoding

    @property
    def value(self):
        if self._value is None:
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

                obj, encoding = ASN1.deserialize(encoding, cls=cls)
                sequence.append(obj)

            self._value = tuple(sequence)

        return self._value

### Composed types ###

class UNSIGNED(INTEGER):
    SIGNED = False

class VarBind(SEQUENCE):
    EXPECTED = [
        OID,
        None,
    ]

class VarBindList(SEQUENCE):
    EXPECTED = VarBind

class PDU(SEQUENCE):
    EXPECTED = [
        INTEGER,
        INTEGER,
        INTEGER,
        VarBindList,
    ]

    def __init__(self, request_id=0, error_status=0, error_index=0, vars=None, encoding=None):
        value = (
            INTEGER(request_id),
            INTEGER(error_status),
            INTEGER(error_index),
            vars,
        ) if vars is not None else ()
        super(PDU, self).__init__(*value, encoding=encoding)

    @property
    def request_id(self):
        return self.value[0]

    @property
    def error_status(self):
        return self.value[1]

    @property
    def error_index(self):
        return self.value[2]

    @property
    def vars(self):
        return self.value[3]

class Message(SEQUENCE):
    EXPECTED = [
        INTEGER,
        OCTET_STRING,
        None,
    ]

    def __init__(self, version=0, community="public", data=None, encoding=None):
        value = (
            INTEGER(version),
            OCTET_STRING(community),
            data,
        ) if data is not None else ()
        super(Message, self).__init__(*value, encoding=encoding)

    @property
    def version(self):
        return self.value[0]

    @property
    def community(self):
        return self.value[1]

    @property
    def data(self):
        return self.value[2]

types = {
    0x02: INTEGER,
    0x04: OCTET_STRING,
    0x06: OID,
    0x30: SEQUENCE,
}

for dtype, cls in types.items():
    cls.TYPE = dtype
