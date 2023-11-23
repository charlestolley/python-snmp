__all__ = ["DesCbc"]

import os

from snmp.security.usm import DecryptionError, PrivProtocol
from snmp.typing import *

from . import *

class DesCbc(PrivProtocol):
    BYTEORDER:  ClassVar[Literal["big"]] = "big"
    CIPHER = DES_CBC

    BLOCKLEN:   ClassVar[int] = CIPHER.BLOCKLEN
    KEYLEN:     ClassVar[int] = BLOCKLEN * 2
    SALTLEN:    ClassVar[int] = BLOCKLEN // 2
    SALTWRAP:   ClassVar[int] = 1 << (8 * SALTLEN)

    def __init__(self, key: bytes) -> None:
        if len(key) < self.KEYLEN:
            errmsg = f"key must be at least {self.KEYLEN} bytes long"
            raise ValueError(errmsg)

        self.key = key[:self.BLOCKLEN]
        self.preIV = key[self.BLOCKLEN:self.KEYLEN]
        self.salt = int.from_bytes(os.urandom(self.SALTLEN), self.BYTEORDER)

    def computeIV(self, salt: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(self.preIV, salt))

    def pad(self, data: bytes) -> bytes:
        n = self.BLOCKLEN - (len(data) % self.BLOCKLEN)
        return data + bytes(n)

    def decrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
        salt: bytes,
    ) -> bytes:
        if len(data) % self.BLOCKLEN:
            errmsg = "DES ciphertext must be a multiple of {} in length"
            raise DecryptionError(errmsg.format(self.BLOCKLEN))

        iv = self.computeIV(salt)
        return Decryptor(self.CIPHER).decrypt(data, self.key, iv)

    def encrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
    ) -> Tuple[bytes, bytes]:
        self.salt = (self.salt + 1) % self.SALTWRAP
        salt = b''.join((
            engineBoots.to_bytes(self.BLOCKLEN - self.SALTLEN, self.BYTEORDER),
            self.salt.to_bytes(self.SALTLEN, self.BYTEORDER),
        ))

        iv = self.computeIV(salt)
        plaintext = self.pad(data)
        ciphertext = Encryptor(self.CIPHER).encrypt(plaintext, self.key, iv)

        return ciphertext, salt
