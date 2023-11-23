__all__ = ["EVP_CIPHER", "EVP_CIPHER_CTX", "ffi", "lib"]

from snmp.cffi import *
from snmp.typing import *

class EVP_CIPHER:
    ...

class EVP_CIPHER_CTX:
    ...

class OpenSSL_FFI(FFI):
    NULL: Pointer[Any]

    @overload
    def new(self, typename: Literal["int*"]) -> Pointer[int]:
        ...

    @overload
    def new(self,
        typename: Literal["unsigned char[]"],
        n: int,
    ) -> UnsignedCharArray:
        ...

class OpenSSL_LIB:
    def EVP_CIPHER_CTX_new(self) -> Pointer[EVP_CIPHER_CTX]:
        ...

    def EVP_CIPHER_CTX_free(self, ctx: Pointer[EVP_CIPHER_CTX]) -> None:
        ...

    def EVP_DecryptInit(self,
        ctx: Pointer[EVP_CIPHER_CTX],
        type: Pointer[EVP_CIPHER],
        key: bytes,
        iv: bytes,
    ) -> int:
        ...

    def EVP_DecryptUpdate(self,
        ctx: Pointer[EVP_CIPHER_CTX],
        out: UnsignedCharArray,
        outl: Pointer[int],
        _in: bytes,
        inl: int,
    ) -> int:
        ...

    def EVP_EncryptInit(self,
        ctx: Pointer[EVP_CIPHER_CTX],
        type: Pointer[EVP_CIPHER],
        key: bytes,
        iv: bytes,
    ) -> int:
        ...

    def EVP_EncryptUpdate(self,
        ctx: Pointer[EVP_CIPHER_CTX],
        out: UnsignedCharArray,
        outl: Pointer[int],
        _in: bytes,
        inl: int,
    ) -> int:
        ...

    def EVP_aes_128_cfb128(self) -> Pointer[EVP_CIPHER]:
        ...

    def EVP_des_cbc(self) -> Pointer[EVP_CIPHER]:
        ...

ffi = OpenSSL_FFI()
lib = OpenSSL_LIB()
