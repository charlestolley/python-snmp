__all__ = [
    "SecurityLevel", "SecurityModel",
    "SecurityModule", "UnknownSecurityModel",
]

from snmp.smi import Sequence

from .levels import SecurityLevel
from .models import *

class SecurityModule:
    def processIncoming(self, message, timestamp = None):
        raise NotImplementedError()

    def prepareOutgoing(self, message, engineID, securityName):
        raise NotImplementedError()
