__all__ = ["Aes128Cfb"]

import os
from snmp.openssl.aes import ffi, lib
from . import DecryptionError

class Aes128Cfb:
    BITS = 128
    INTSIZE = 4
    BYTEORDER = "big"

    BLOCKLEN = BITS // 8
    KEYLEN = BLOCKLEN
    SALTLEN = BLOCKLEN - (2 * INTSIZE)
    SALTWRAP = 1 << (8 * SALTLEN)

    def __init__(self, key):
        if len(key) < self.KEYLEN:
            errmsg = "key must be at least {} bytes long".format(self.KEYLEN)
            raise ValueError(errmsg)

        self.key = ffi.new("AES_KEY*")
        result = lib.AES_set_encrypt_key(key[:self.KEYLEN], self.BITS, self.key)
        assert result == 0

        self.salt = int.from_bytes(os.urandom(self.SALTLEN), self.BYTEORDER)

    def packIV(self, engineBoots, engineTime, salt):
        if len(salt) != self.SALTLEN:
            raise ValueError("Invalid salt")

        return b''.join((
            engineBoots.to_bytes(self.INTSIZE, self.BYTEORDER),
            engineTime .to_bytes(self.INTSIZE, self.BYTEORDER),
            salt
        ))

    def compute(self, data, iv, mode):
        num = ffi.new("int*", 0)
        iv = ffi.new("unsigned char[]", iv)
        output = ffi.new("unsigned char[]", len(data))
        lib.AES_cfb128_encrypt(data, output, len(data), self.key, iv, num, mode)
        return bytes(output)

    def decrypt(self, data, engineBoots, engineTime, salt):
        try:
            iv = self.packIV(engineBoots, engineTime, salt)
        except ValueError as err:
            raise DecryptionError(err) from err

        return self.compute(data, iv, lib.AES_DECRYPT);

    def encrypt(self, data, engineBoots, engineTime):
        self.salt = (self.salt + 1) % self.SALTWRAP
        salt = self.salt.to_bytes(self.SALTLEN, self.BYTEORDER)
        iv = self.packIV(engineBoots, engineTime, salt)
        return salt, self.compute(data, iv, lib.AES_ENCRYPT)
