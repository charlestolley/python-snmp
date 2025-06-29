__all__ = ["BadVersion", "ProtocolVersion", "VersionOnlyMessage"]

import enum

from snmp.asn1 import *
from snmp.ber import *
from snmp.exception import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *

class BadVersion(IncomingMessageError):
    def __init__(self, msg: str, data: subbytes):
        super().__init__(msg)
        self.data = data

class ProtocolVersion(enum.IntEnum):
    SNMPv1  = 0
    SNMPv2c = 1
    SNMPv3  = 3

    # Python 3.11 changes IntEnum.__str__()
    __str__ = enum.Enum.__str__

@final
class VersionOnlyMessage(Sequence):
    def __init__(self, version: ProtocolVersion) -> None:
        self.version = version

    def __iter__(self) -> Iterator[ASN1]:
        yield Integer(self.version)

    def __len__(self) -> int:
        return 1

    def __repr__(self) -> str:
        return f"{typename(self)}({str(self.version)})"

    @classmethod
    def deserialize(cls,
        data: Asn1Data,
    ) -> "VersionOnlyMessage":
        msgVersion, _ = Integer.decode(data)

        try:
            version = ProtocolVersion(msgVersion.value)
        except ValueError as err:
            raise ASN1.DeserializeError(err.args[0], BadVersion) from err

        return cls(version)
