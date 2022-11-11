from snmp.cffi import *
from snmp.typing import *

class DES_cblock:
    def __getitem__(self, index: int) -> int: ...
    def __setitem__(self, index: int, value: int) -> None: ...

class DES_key_schedule:
    ...

class OpenSSL_DES_FFI(FFI):
    @overload
    def new(self,
        typename: Literal["unsigned char[]"],
        size: int,
    ) -> UnsignedCharArray:
        ...

    @overload
    def new(self,
        typename: Literal["DES_cblock*"],
        init: Optional[bytes] = None,
    ) -> Pointer[DES_cblock]:
        ...

    @overload
    def new(self,
        typename: Literal["DES_key_schedule*"],
    ) -> Pointer[DES_key_schedule]:
        ...

class OpenSSL_DES_LIB:
    DES_DECRYPT: ClassVar[int]
    DES_ENCRYPT: ClassVar[int]

    def DES_set_odd_parity(self, key: Pointer[DES_cblock]) -> None:
        ...

    def DES_set_key_unchecked(self,
        key: Pointer[DES_cblock],
        schedule: Pointer[DES_key_schedule],
    ) -> None:
        ...

    def DES_cbc_encrypt(self,
        input: bytes,
        output: UnsignedCharArray,
        length: int,
        schedule: Pointer[DES_key_schedule],
        ivec: Pointer[DES_cblock],
        enc: int,
    ) -> None:
        ...

ffi = OpenSSL_DES_FFI()
lib = OpenSSL_DES_LIB()
