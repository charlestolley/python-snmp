from snmp.security.usm import PrivProtocol
from snmp.typing import *

class AesCfb128(PrivProtocol):
    def __init__(self, key: bytes) -> None:
        ...

    def decrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
        salt: bytes,
    ) -> bytes:
        ...

    def encrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
    ) -> Tuple[bytes, bytes]:
        ...

class DesCbc(PrivProtocol):
    def __init__(self, key: bytes) -> None:
        ...

    def decrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
        salt: bytes,
    ) -> bytes:
        ...

    def encrypt(self,
        data: bytes,
        engineBoots: int,
        engineTime: int,
    ) -> Tuple[bytes, bytes]:
        ...
