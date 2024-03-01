__all__ = [
    "InvalidEngineID", "InvalidSecurityLevel", "InvalidUserName",
    "AuthProtocol", "PrivProtocol", "UserBasedSecurityModule",
]

from snmp.exception import *
from snmp.typing import *

class DecryptionError(IncomingMessageError):
    pass

class AuthProtocol:
    def __init__(self, key: bytes) -> None:
        raise NotImplementedError()

    @classmethod
    def computeKey(cls, secret: bytes) -> bytes:
        raise NotImplementedError()

    @classmethod
    def localizeKey(cls, key: bytes, engineID: bytes) -> bytes:
        raise NotImplementedError()

    @classmethod
    def localize(cls, secret: bytes, engineID: bytes) -> bytes:
        return cls.localizeKey(cls.computeKey(secret), engineID)

    @property
    def msgAuthenticationParameters(self) -> bytes:
        raise NotImplementedError()

    def sign(self, data: bytes) -> bytes:
        raise NotImplementedError()

class PrivProtocol:
    def __init__(self, key: bytes) -> None:
        raise NotImplementedError()

    def decrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
        salt: bytes,
    ) -> bytes:
        raise NotImplementedError()

    def encrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
    ) -> Tuple[bytes, bytes]:
        raise NotImplementedError()

from .implementation import *
from .users import *
