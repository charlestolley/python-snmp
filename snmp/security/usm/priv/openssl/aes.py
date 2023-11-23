__all__ = ["AesCfb128"]

import os

from snmp.security.usm import DecryptionError, PrivProtocol
from snmp.typing import *

from . import *

class AesCfb128(PrivProtocol):
    BYTEORDER:  ClassVar[Literal["big"]] = "big"
    CIPHER = AES_128_CFB128

    INTSIZE:    ClassVar[int] = 4
    KEYLEN:     ClassVar[int] = CIPHER.BLOCKLEN
    SALTLEN:    ClassVar[int] = CIPHER.BLOCKLEN - (2 * INTSIZE)
    SALTWRAP:   ClassVar[int] = 1 << (8 * SALTLEN)

    def __init__(self, key: bytes) -> None:
        if len(key) < self.KEYLEN:
            errmsg = "key must be at least {} bytes long".format(self.KEYLEN)
            raise ValueError(errmsg)

        self.key = key[:self.KEYLEN]
        self.salt = int.from_bytes(os.urandom(self.SALTLEN), self.BYTEORDER)

    def packIV(self, engineBoots: int, engineTime: int, salt: bytes) -> bytes:
        if len(salt) != self.SALTLEN:
            raise ValueError("Invalid salt")

        return b''.join((
            engineBoots.to_bytes(self.INTSIZE, self.BYTEORDER),
            engineTime .to_bytes(self.INTSIZE, self.BYTEORDER),
            salt
        ))

    def decrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
        salt: bytes,
    ) -> bytes:
        try:
            iv = self.packIV(engineBoots, engineTime, salt)
        except ValueError as err:
            raise DecryptionError(err) from err

        return Decryptor(self.CIPHER).decrypt(data, self.key, iv)

    def encrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
    ) -> Tuple[bytes, bytes]:
        self.salt = (self.salt + 1) % self.SALTWRAP

        salt = self.salt.to_bytes(self.SALTLEN, self.BYTEORDER)
        iv = self.packIV(engineBoots, engineTime, salt)
        ciphertext = Encryptor(self.CIPHER).encrypt(data, self.key, iv)

        return ciphertext, salt
