from snmp.exception import IncomingMessageError

class DecryptionError(IncomingMessageError):
    pass

from .aes import *
from .des import *
