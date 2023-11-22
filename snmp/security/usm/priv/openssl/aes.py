__all__ = ["AesCfb128"]

import os

from snmp.openssl.aes import ffi, lib
from snmp.security.usm import DecryptionError, PrivProtocol
from snmp.typing import *

class AesCfb128(PrivProtocol):
    BYTEORDER:  ClassVar[Literal["big"]] = "big"

    BITS:       ClassVar[int] = 128
    INTSIZE:    ClassVar[int] = 4
    BLOCKLEN:   ClassVar[int] = BITS // 8
    KEYLEN:     ClassVar[int] = BLOCKLEN
    SALTLEN:    ClassVar[int] = BLOCKLEN - (2 * INTSIZE)
    SALTWRAP:   ClassVar[int] = 1 << (8 * SALTLEN)

    def __init__(self, key: bytes) -> None:
        if len(key) < self.KEYLEN:
            errmsg = "key must be at least {} bytes long".format(self.KEYLEN)
            raise ValueError(errmsg)

        self.key = ffi.new("AES_KEY*")
        error = lib.AES_set_encrypt_key(key[:self.KEYLEN], self.BITS, self.key)
        assert error == 0

        self.salt = int.from_bytes(os.urandom(self.SALTLEN), self.BYTEORDER)

    def packIV(self, engineBoots: int, engineTime: int, salt: bytes) -> bytes:
        if len(salt) != self.SALTLEN:
            raise ValueError("Invalid salt")

        return b''.join((
            engineBoots.to_bytes(self.INTSIZE, self.BYTEORDER),
            engineTime .to_bytes(self.INTSIZE, self.BYTEORDER),
            salt
        ))

    def compute(self, data: bytes, iv: bytes, mode: int) -> bytes:
        n = ffi.new("int*", 0)
        _iv = ffi.new("unsigned char[]", iv)
        output = ffi.new("unsigned char[]", len(data))
        lib.AES_cfb128_encrypt(data, output, len(data), self.key, _iv, n, mode)
        return bytes(output)

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

        return self.compute(data, iv, lib.AES_DECRYPT);

    def encrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
    ) -> Tuple[bytes, bytes]:
        self.salt = (self.salt + 1) % self.SALTWRAP
        salt = self.salt.to_bytes(self.SALTLEN, self.BYTEORDER)
        iv = self.packIV(engineBoots, engineTime, salt)
        return self.compute(data, iv, lib.AES_ENCRYPT), salt
