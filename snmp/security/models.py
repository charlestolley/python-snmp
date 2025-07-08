__all__ = ["SecurityModel", "UnknownSecurityModel"]

import enum

from snmp.exception import IncomingMessageErrorWithPointer

class UnknownSecurityModel(IncomingMessageErrorWithPointer):
    pass

class SecurityModel(enum.IntEnum):
    USM = 3
