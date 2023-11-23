__all__ = ["FFI", "Pointer", "UnsignedCharArray"]

from snmp.typing import *

T = TypeVar("T")
class Pointer(Generic[T]):
    def __getitem__(self, index: Literal[0]) -> T: ...

class UnsignedCharArray:
    def __bytes__(self) -> bytes: ...

class FFI:
    def memmove(self, dest: Pointer[T], src: Pointer[T], n: int) -> None: ...
    def sizeof(self, typename: str) -> int: ...
