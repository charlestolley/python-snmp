__all__ = ["BadVersion", "ProtocolVersion", "VersionOnlyMessage"]

import enum

from snmp.asn1 import *
from snmp.ber import *
from snmp.exception import *
from snmp.smi import *
from snmp.utils import *

class BadVersion(IncomingMessageErrorWithPointer):
    pass

class ProtocolVersion(enum.IntEnum):
    SNMPv1  = 0
    SNMPv2c = 1
    SNMPv3  = 3

    # Python 3.11 changes IntEnum.__str__()
    __str__ = enum.Enum.__str__

class VersionOnlyMessage(Sequence):
    def __init__(self, version):
        self.version = version

    def __iter__(self):
        yield Integer(self.version)

    def __len__(self):
        return 1

    def __repr__(self):
        return f"{typename(self)}({str(self.version)})"

    @classmethod
    def deserialize(cls, data):
        msgVersion, tail = Integer.decode(data)

        try:
            version = ProtocolVersion(msgVersion.value)
        except ValueError as err:
            errmsg = f"Invalid msgVersion: {msgVersion.value}"
            raise BadVersion(errmsg, data, tail) from err

        return cls(version)
