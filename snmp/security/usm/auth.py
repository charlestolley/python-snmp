__all__ = [
    "HmacMd5", "HmacSha", "HmacSha224", "HmacSha256", "HmacSha384", "HmacSha512"
]

import hashlib
import hmac

class AuthProtocol:
    def __init__(self, key):
        self.key = key

    @classmethod
    def localize(cls, secret, engineID):
        repeat, truncate = divmod(1 << 20, len(secret))

        context = cls.ALGORITHM()
        for i in range(repeat):
            context.update(secret)

        context.update(secret[:truncate])
        key = context.digest()

        context = cls.ALGORITHM()
        context.update(key)
        context.update(engineID)
        context.update(key)
        return context.digest()

    @property
    def msgAuthenticationParameters(self):
        return b'\0' * self.N

    def sign(self, data):
        context = hmac.new(self.key, digestmod=self.ALGORITHM)
        context.update(data)
        return context.digest()[:self.N]

class HmacMd5(AuthProtocol):
    ALGORITHM = hashlib.md5
    N = 12

class HmacSha(AuthProtocol):
    ALGORITHM = hashlib.sha1
    N = 12

class HmacSha224(AuthProtocol):
    ALGORITHM = hashlib.sha224
    N = 16

class HmacSha256(AuthProtocol):
    ALGORITHM = hashlib.sha256
    N = 24

class HmacSha384(AuthProtocol):
    ALGORITHM = hashlib.sha384
    N = 32

class HmacSha512(AuthProtocol):
    ALGORITHM = hashlib.sha512
    N = 48
