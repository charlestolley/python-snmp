__all__ = ["DesCbc"]

import os

from snmp.smi import OID
from snmp.security.usm import PrivProtocol

from . import *

class DesCbc(PrivProtocol):
    BYTEORDER = "big"
    CIPHER = DES_CBC

    BLOCKLEN = CIPHER.BLOCKLEN
    KEYLEN = BLOCKLEN * 2
    SALTLEN = BLOCKLEN // 2
    SALTWRAP = 1 << (8 * SALTLEN)

    def __init__(self, key):
        if len(key) < self.KEYLEN:
            raise ValueError(f"key must be at least {self.KEYLEN} bytes long")

        self.algorithm = OID.parse("1.3.6.1.6.3.10.1.2.2")
        self.key = key[:self.BLOCKLEN]
        self.preIV = key[self.BLOCKLEN:self.KEYLEN]
        self.salt = int.from_bytes(os.urandom(self.SALTLEN), self.BYTEORDER)

    def __eq__(self, other):
        try:
            return (self.algorithm == other.algorithm
                and self.key == other.key
                and self.preIV == other.preIV)
        except AttributeError:
            return NotImplemented

    def computeIV(self, salt):
        return bytes(a ^ b for a, b in zip(self.preIV, salt))

    def pad(self, data):
        n = self.BLOCKLEN - (len(data) % self.BLOCKLEN)
        return data + bytes(n)

    def decrypt(self, data, engineBoots, engineTime, salt):
        if len(data) % self.BLOCKLEN:
            errmsg = "DES ciphertext must be a multiple of {} in length"
            raise ValueError(errmsg.format(self.BLOCKLEN))

        iv = self.computeIV(salt)
        return Decryptor(self.CIPHER).decrypt(data, self.key, iv)

    def encrypt(self, data, engineBoots, engineTime):
        self.salt = (self.salt + 1) % self.SALTWRAP
        salt = b''.join((
            engineBoots.to_bytes(self.BLOCKLEN - self.SALTLEN, self.BYTEORDER),
            self.salt.to_bytes(self.SALTLEN, self.BYTEORDER),
        ))

        iv = self.computeIV(salt)
        plaintext = self.pad(data)
        ciphertext = Encryptor(self.CIPHER).encrypt(plaintext, self.key, iv)

        return ciphertext, salt
