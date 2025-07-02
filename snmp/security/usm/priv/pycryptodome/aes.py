__all__ = ["AesCfb128"]

import os

from Crypto.Cipher import AES

from snmp.smi import OID
from snmp.security.usm import PrivProtocol
from snmp.typing import *

class AesCfb128(PrivProtocol):
    BYTEORDER:  ClassVar[Literal["big"]] = "big"

    BITS:           ClassVar[int] = 128
    INTSIZE:        ClassVar[int] = 4
    BLOCKLEN:       ClassVar[int] = BITS // 8
    KEYLEN:         ClassVar[int] = BLOCKLEN
    SALTLEN:        ClassVar[int] = BLOCKLEN - (2 * INTSIZE)
    SALTWRAP:       ClassVar[int] = 1 << (8 * SALTLEN)
    SEGMENT_SIZE:   ClassVar[int] = 128

    def __init__(self, key: bytes) -> None:
        if len(key) < self.KEYLEN:
            raise ValueError(f"key must be at least {self.KEYLEN} bytes long")

        self.algorithm = OID.parse("1.3.6.1.6.3.10.1.2.4")
        self.key = key[:self.KEYLEN]
        self.salt = int.from_bytes(os.urandom(self.SALTLEN), self.BYTEORDER)

    def __eq__(self, other: object) -> bool:
        try:
            return self.algorithm == other.algorithm and self.key == other.key
        except AttributeError:
            return NotImplemented

    def newCipher(self, iv: bytes):
        return AES.new(
            self.key,
            AES.MODE_CFB,
            iv=iv,
            segment_size=self.SEGMENT_SIZE,
        )

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
        iv = self.packIV(engineBoots, engineTime, salt)
        return self.newCipher(iv).decrypt(data)

    def encrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
    ) -> Tuple[bytes, bytes]:
        self.salt = (self.salt + 1) % self.SALTWRAP

        salt = self.salt.to_bytes(self.SALTLEN, self.BYTEORDER)
        iv = self.packIV(engineBoots, engineTime, salt)
        ciphertext = self.newCipher(iv).encrypt(data)

        return ciphertext, salt
