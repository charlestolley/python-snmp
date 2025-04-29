__all__ = ["SecurityModel", "UnknownSecurityModel"]

import enum
from snmp.exception import IncomingMessageError

class UnknownSecurityModel(IncomingMessageError):
    pass

class SecurityModel(enum.IntEnum):
    USM = 3
