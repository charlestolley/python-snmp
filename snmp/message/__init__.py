__all__ = ["Message", "MessageBase", "MessageProcessingModel", "RequestHandle"]

from abc import abstractmethod
import enum

from snmp.ber import *
from snmp.types import *
from snmp.utils import *

class MessageProcessingModel(enum.IntEnum):
    SNMPv1  = 0
    SNMPv2c = 1
    SNMPv3  = 3

class MessageBase(Sequence):
    @staticmethod
    def decodeVersion(data):
        ptr = decode(data, expected=SEQUENCE, copy=False)
        version, ptr = Integer.decode(ptr, leftovers=True)
        return version.value, ptr

    @classmethod
    @abstractmethod
    def decodeBody(cls, data, types, version=MessageProcessingModel.SNMPv1):
        ...

    @classmethod
    def deserialize(cls, data, types):
        version, ptr = cls.decodeVersion(data)
        return cls.decodeBody(ptr, types, version)

class Message(MessageBase):
    def __init__(self, version, community, pdu):
        self.version = version
        self.community = community
        self.pdu = pdu

    def __iter__(self):
        yield Integer(self.version)
        yield OctetString(self.community)
        yield self.pdu

    def __len__(self):
        return 3

    def __repr__(self):
        return f"{typename(self)}({self.community!r}, {repr(self.pdu)})"

    def __str__(self):
        return self.toString()

    def toString(self, depth=0, tab="    "):
        indent = tab * depth
        subindent = indent + tab
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Community: {self.community!r}",
            f"{self.pdu.toString(depth+1, tab)}",
        ))

    @classmethod
    def decodeBody(cls, data, types, version=MessageProcessingModel.SNMPv1):
        if types is None:
            types = dict()

        community, data = OctetString.decode(data, leftovers=True)
        identifier = decode_identifier(subbytes(data))

        try:
            pduType = types[identifier]
        except KeyError as err:
            raise ParseError(f"Invalid PDU type: {identifier}") from err

        return cls(version, community.data, pduType.decode(data))

class RequestHandle:
    @abstractmethod
    def addCallback(self, func, idNum):
        ...

    @abstractmethod
    def push(self, response):
        ...
