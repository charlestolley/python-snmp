__all__ = [
    "HmacMd5", "HmacSha",
    "HmacSha224", "HmacSha256", "HmacSha384", "HmacSha512"
]

import hashlib
import hmac

from snmp.security.usm import AuthProtocol
from snmp.typing import *

class HmacAuthProtocol(AuthProtocol):
    ALGORITHM:  ClassVar[Callable[..., "hashlib._Hash"]]
    N:          ClassVar[int]

    def __init__(self, key: bytes) -> None:
        self.key = key

    @classmethod
    def computeKey(cls, secret: bytes) -> bytes:
        repeat, truncate = divmod(1 << 20, len(secret))

        context = cls.ALGORITHM()
        for i in range(repeat):
            context.update(secret)

        context.update(secret[:truncate])
        return context.digest()

    @classmethod
    def localizeKey(cls, key: bytes, engineID: bytes) -> bytes:
        context = cls.ALGORITHM()
        context.update(key)
        context.update(engineID)
        context.update(key)
        return context.digest()

    @property
    def msgAuthenticationParameters(self) -> bytes:
        return bytes(self.N)

    def sign(self, data: bytes) -> bytes:
        context = hmac.new(self.key, digestmod=self.ALGORITHM)
        context.update(data)
        return context.digest()[:self.N]

class HmacMd5(HmacAuthProtocol):
    ALGORITHM = hashlib.md5
    N = 12

class HmacSha(HmacAuthProtocol):
    ALGORITHM = hashlib.sha1
    N = 12

class HmacSha224(HmacAuthProtocol):
    ALGORITHM = hashlib.sha224
    N = 16

class HmacSha256(HmacAuthProtocol):
    ALGORITHM = hashlib.sha256
    N = 24

class HmacSha384(HmacAuthProtocol):
    ALGORITHM = hashlib.sha384
    N = 32

class HmacSha512(HmacAuthProtocol):
    ALGORITHM = hashlib.sha512
    N = 48
