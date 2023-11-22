__all__ = ["DesCbc"]

import os
from snmp.openssl.des import ffi, lib
from snmp.security.usm import DecryptionError, PrivProtocol
from snmp.typing import *

class DesCbc(PrivProtocol):
    BYTEORDER:  ClassVar[Literal["big"]] = "big"

    BLOCKLEN:   ClassVar[int] = ffi.sizeof("DES_cblock")
    KEYLEN:     ClassVar[int] = BLOCKLEN * 2
    SALTLEN:    ClassVar[int] = BLOCKLEN // 2
    SALTWRAP:   ClassVar[int] = 1 << (8 * SALTLEN)

    def __init__(self, key: bytes) -> None:
        if len(key) < self.KEYLEN:
            errmsg = f"key must be at least {self.KEYLEN} bytes long"
            raise ValueError(errmsg)

        _key, self.preIV = (
            ffi.new("DES_cblock*", key[:self.BLOCKLEN]),
            ffi.new("DES_cblock*", key[self.BLOCKLEN:self.KEYLEN])
        )

        self.key = ffi.new("DES_key_schedule*")
        lib.DES_set_odd_parity(_key)
        lib.DES_set_key_unchecked(_key, self.key)

        self.salt = int.from_bytes(os.urandom(self.SALTLEN), self.BYTEORDER)

    def compute(self, data: bytes, salt: bytes, mode: int) -> bytes:
        iv = ffi.new("DES_cblock*")
        ffi.memmove(iv, self.preIV, self.BLOCKLEN)

        for i in range(self.BLOCKLEN):
            iv[0][i] ^= salt[i]

        output = ffi.new("unsigned char[]", len(data))
        lib.DES_cbc_encrypt(data, output, len(data), self.key, iv, mode)
        return bytes(output)

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

        return self.compute(data, salt, lib.DES_DECRYPT)

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

        return self.compute(self.pad(data), salt, lib.DES_ENCRYPT), salt
