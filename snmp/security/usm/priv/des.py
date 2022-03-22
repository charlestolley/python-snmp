__all__ = ["DesCbc"]

import os
from snmp.openssl.des import ffi, lib
from . import DecryptionError

class DesCbc:
    BYTEORDER = "big"
    BLOCKLEN = ffi.sizeof("DES_cblock")
    KEYLEN = BLOCKLEN * 2
    SALTLEN = BLOCKLEN // 2
    SALTWRAP = 1 << (8 * SALTLEN)

    def __init__(self, key):
        if len(key) < self.KEYLEN:
            errmsg = "key must be at least {} bytes long".format(self.KEYLEN)
            raise ValueError(errmsg)

        key, self.preIV = (
            ffi.new("DES_cblock*", key[:self.BLOCKLEN]),
            ffi.new("DES_cblock*", key[self.BLOCKLEN:self.KEYLEN])
        )

        self.key = ffi.new("DES_key_schedule*")
        lib.DES_set_odd_parity(key)
        lib.DES_set_key_unchecked(key, self.key)

        self.salt = int.from_bytes(os.urandom(self.SALTLEN), self.BYTEORDER)

    def compute(self, data, salt, mode):
        iv = ffi.new("DES_cblock*")
        ffi.memmove(iv, self.preIV, self.BLOCKLEN)

        for i in range(self.BLOCKLEN):
            iv[0][i] ^= salt[i]

        output = ffi.new("unsigned char[]", len(data))
        lib.DES_cbc_encrypt(data, output, len(data), self.key, iv, mode)
        return bytes(output)

    def pad(self, data):
        n = self.BLOCKLEN - (len(data) % self.BLOCKLEN)
        return (data + (b'\0' * n)) if n else data

    def decrypt(self, data, engineBoots, engineTime, salt):
        if len(data) % self.BLOCKLEN:
            errmsg = "DES ciphertext must be a multiple of {} in length"
            raise DecryptionError(errmsg.format(self.BLOCKLEN))

        return self.compute(data, salt, lib.DES_DECRYPT)

    def encrypt(self, data, engineBoots, engineTime):
        self.salt = (self.salt + 1) % self.SALTWRAP
        salt = b''.join((
            engineBoots.to_bytes(self.BLOCKLEN - self.SALTLEN, self.BYTEORDER),
            self.salt.to_bytes(self.SALTLEN, self.BYTEORDER),
        ))

        return salt, self.compute(self.pad(data), salt, lib.DES_ENCRYPT)
