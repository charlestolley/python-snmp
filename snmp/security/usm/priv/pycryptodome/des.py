__all__ = ["DesCbc"]

import os

from Crypto.Cipher import DES

from snmp.smi import OID
from snmp.security.usm import PrivProtocol

class DesCbc(PrivProtocol):
    BYTEORDER = "big"

    BLOCKLEN = 8
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

    def newCipher(self, iv):
        return DES.new(self.key, DES.MODE_CBC, iv=iv)

    def pad(self, data):
        n = self.BLOCKLEN - (len(data) % self.BLOCKLEN)
        return data + bytes(n)

    def decrypt(self, data, engineBoots, engineTime, salt):
        if len(data) % self.BLOCKLEN:
            errmsg = "DES ciphertext must be a multiple of {} in length"
            raise ValueError(errmsg.format(self.BLOCKLEN))

        return self.newCipher(self.computeIV(salt)).decrypt(self.pad(data))

    def encrypt(self, data, engineBoots, engineTime):
        self.salt = (self.salt + 1) % self.SALTWRAP
        salt = b''.join((
            engineBoots.to_bytes(self.BLOCKLEN - self.SALTLEN, self.BYTEORDER),
            self.salt.to_bytes(self.SALTLEN, self.BYTEORDER),
        ))

        iv = self.computeIV(salt)
        ciphertext = self.newCipher(iv).encrypt(self.pad(data))

        return ciphertext, salt
