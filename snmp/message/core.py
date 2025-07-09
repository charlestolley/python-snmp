__all__ = ["Message"]

from snmp.ber import ParseError, Tag
from snmp.smi import *
from snmp.utils import *

from .version import *

class Message(Sequence):
    VERSIONS = (ProtocolVersion.SNMPv1, ProtocolVersion.SNMPv2c)

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
        return "{}({}, {!r}, {})".format(
            typename(self),
            str(self.version),
            self.community,
            repr(self.pdu),
        )

    def __str__(self):
        return self.toString()

    def toString(self, depth = 0, tab = "    "):
        indent = tab * depth
        subindent = indent + tab
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Community: {self.community!r}",
            f"{self.pdu.toString(depth+1, tab)}",
        ))

    @classmethod
    def deserialize(cls, data, types = None):
        msgVersion, ptr = Integer.decode(data)

        try:
            version = ProtocolVersion(msgVersion.value)
        except ValueError as err:
            errmsg = f"Invalid msgVersion: {msgVersion.value}"
            raise BadVersion(errmsg, data, ptr) from err

        if version not in cls.VERSIONS:
            errmsg = f"{typename(cls)} does not support {version.name}"
            raise BadVersion(errmsg, data, ptr)

        community, ptr = OctetString.decode(ptr)
        tag, _ = Tag.decode(subbytes(ptr))

        if types is None:
            types = dict()

        try:
            pduType = types[tag]
        except KeyError as err:
            raise ParseError(f"Invalid PDU type: {tag}", ptr) from err

        return cls(
            version,
            community.data,
            pduType.decodeExact(ptr),
        )
