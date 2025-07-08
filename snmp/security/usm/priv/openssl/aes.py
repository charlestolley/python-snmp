__all__ = ["AesCfb128"]

import os

from snmp.smi import OID
from snmp.security.usm import PrivProtocol

from . import *

class AesCfb128(PrivProtocol):
    BYTEORDER = "big"
    CIPHER = AES_128_CFB128

    INTSIZE = 4
    KEYLEN = CIPHER.BLOCKLEN
    SALTLEN = CIPHER.BLOCKLEN - (2 * INTSIZE)
    SALTWRAP = 1 << (8 * SALTLEN)

    def __init__(self, key):
        if len(key) < self.KEYLEN:
            raise ValueError(f"key must be at least {self.KEYLEN} bytes long")

        self.algorithm = OID.parse("1.3.6.1.6.3.10.1.2.4")
        self.key = key[:self.KEYLEN]
        self.salt = int.from_bytes(os.urandom(self.SALTLEN), self.BYTEORDER)

    def __eq__(self, other):
        try:
            return self.algorithm == other.algorithm and self.key == other.key
        except AttributeError:
            return NotImplemented

    def packIV(self, engineBoots, engineTime, salt):
        if len(salt) != self.SALTLEN:
            raise ValueError("Invalid salt")

        return b''.join((
            engineBoots.to_bytes(self.INTSIZE, self.BYTEORDER),
            engineTime .to_bytes(self.INTSIZE, self.BYTEORDER),
            salt
        ))

    def decrypt(self, data, engineBoots, engineTime, salt):
        iv = self.packIV(engineBoots, engineTime, salt)
        return Decryptor(self.CIPHER).decrypt(data, self.key, iv)

    def encrypt(self, data, engineBoots, engineTime):
        self.salt = (self.salt + 1) % self.SALTWRAP

        salt = self.salt.to_bytes(self.SALTLEN, self.BYTEORDER)
        iv = self.packIV(engineBoots, engineTime, salt)
        ciphertext = Encryptor(self.CIPHER).encrypt(data, self.key, iv)

        return ciphertext, salt
