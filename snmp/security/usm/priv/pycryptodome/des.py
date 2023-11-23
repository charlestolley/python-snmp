__all__ = ["DesCbc"]

import os

from Crypto.Cipher import DES
from Crypto.Cipher._mode_cbc import CbcMode

from snmp.security.usm import DecryptionError, PrivProtocol
from snmp.typing import *

class DesCbc(PrivProtocol):
    BYTEORDER:  ClassVar[Literal["big"]] = "big"

    BLOCKLEN:   ClassVar[int] = 8
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

    def newCipher(self, iv: bytes) -> CbcMode:
        return cast(CbcMode, DES.new(self.key, DES.MODE_CBC, iv=iv))

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

        return self.newCipher(self.computeIV(salt)).decrypt(self.pad(data))

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
        ciphertext = self.newCipher(iv).encrypt(self.pad(data))

        return ciphertext, salt
