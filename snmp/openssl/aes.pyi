from snmp.cffi import *
from snmp.typing import *

class Int:
    ...

class AES_KEY:
    ...

class OpenSSL_AES_FFI(FFI):
    @overload
    def new(self, typename: Literal["int*"], value: int) -> Pointer[Int]:
        ...

    @overload
    def new(self,
        typename: Literal["unsigned char[]"],
        data: bytes,
    ) -> UnsignedCharArray:
        ...

    @overload
    def new(self,
        typename: Literal["unsigned char[]"],
        size: int,
    ) -> UnsignedCharArray:
        ...

    @overload
    def new(self, typename: Literal["AES_KEY*"]) -> Pointer[AES_KEY]:
        ...

class OpenSSL_AES_LIB:
    AES_DECRYPT: ClassVar[int]
    AES_ENCRYPT: ClassVar[int]

    def AES_set_encrypt_key(self,
        userKey: bytes,
        bits: int,
        key: Pointer[AES_KEY],
    ) -> int:
        ...

    def AES_cfb128_encrypt(self,
        data: bytes,
        output: UnsignedCharArray,
        length: int,
        key: Pointer[AES_KEY],
        ivec: UnsignedCharArray,
        num: Pointer[Int],
        enc: int,
    ) -> None:
        ...

ffi = OpenSSL_AES_FFI()
lib = OpenSSL_AES_LIB()
