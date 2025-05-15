__all__ = ["SignedUsmParameters", "UnsignedUsmParameters"]

from snmp.asn1 import ASN1
from snmp.ber import *
from snmp.exception import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *

class UnsignedUsmParameters(Sequence):
    def __init__(self,
        engineID: bytes,
        engineBoots: int,
        engineTime: int,
        userName: bytes,
        padding: bytes,
        salt: bytes,
    ):
        if engineBoots < 0:
            raise ValueError(f"negative value for engineBoots: {engineBoots}")
        elif engineTime < 0:
            raise ValueError(f"negative value for engineTime: {engineTime}")
        elif len(userName) > 32:
            raise ValueError(f"userName exceeds 32 characters: {userName!r}")

        self._engineID = OctetString(engineID)
        self._engineBoots = Integer(engineBoots)
        self._engineTime = Integer(engineTime)
        self._userName = OctetString(userName)
        self._padding = OctetString(padding)
        self._salt = OctetString(salt)

    @property
    def engineID(self) -> bytes:
        return self._engineID.data

    @property
    def engineBoots(self) -> int:
        return self._engineBoots.value

    @property
    def engineTime(self) -> int:
        return self._engineTime.value

    @property
    def userName(self) -> bytes:
        return self._userName.data

    @property
    def padding(self) -> bytes:
        return self._padding.data

    @property
    def salt(self) -> bytes:
        return self._salt.data

    def __iter__(self) -> Iterator[ASN1]:
        yield self._engineID
        yield self._engineBoots
        yield self._engineTime
        yield self._userName
        yield self._padding
        yield self._salt

    def __len__(self) -> int:
        return 6

    def __repr__(self) -> str:
        args = (
            str(self.engineID),
            str(self.engineBoots),
            str(self.engineTime),
            str(self.userName),
            str(self.padding),
            str(self.salt),
        )

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Authoritative Engine ID: {self.engineID!r}",
            f"{subindent}Authoritative Engine Boots: {self.engineBoots}",
            f"{subindent}Authoritative Engine Time: {self.engineTime}",
            f"{subindent}User Name: {self.userName!r}",
            f"{subindent}Authentication Padding: {self.padding!r}",
            f"{subindent}Encryption Salt: {self.salt!r}",
        ))

    @classmethod
    def deserialize(cls,
        data: Union[bytes, subbytes],
    ) -> "UnsignedUsmParameters":
        engineID, ptr   = OctetString.decode(data)
        engineBoots, ptr= Integer.decode(ptr)
        engineTime, ptr = Integer.decode(ptr)
        userName, ptr   = OctetString.decode(ptr)
        padding, ptr    = OctetString.decode(ptr)
        salt            = OctetString.decodeExact(ptr)

        try:
            return cls(
                engineID.data,
                engineBoots.value,
                engineTime.value,
                userName.data,
                padding.data,
                salt.data,
            )
        except ValueError as err:
            raise ParseError(*err.args) from err

    @classmethod
    def findPadding(self, msgSecurityParameters: subbytes) -> subbytes:
        tag, ptr, tail          = decode(msgSecurityParameters)
        tag, engineID, ptr      = decode(ptr)
        tag, engineBoots, ptr   = decode(ptr)
        tag, engineTime, ptr    = decode(ptr)
        tag, userName, ptr      = decode(ptr)
        tag, ptr, tail          = decode(ptr)
        return ptr

class SignedUsmParameters(Sequence):
    def __init__(self,
        engineID: bytes,
        engineBoots: int,
        engineTime: int,
        userName: bytes,
        signature: subbytes,
        salt: bytes,
    ):
        if engineBoots < 0:
            raise ValueError(f"negative value for engineBoots: {engineBoots}")
        elif engineTime < 0:
            raise ValueError(f"negative value for engineTime: {engineTime}")
        elif len(userName) > 32:
            raise ValueError(f"userName exceeds 32 characters: {userName!r}")

        self._engineID = OctetString(engineID)
        self._engineBoots = Integer(engineBoots)
        self._engineTime = Integer(engineTime)
        self._userName = OctetString(userName)
        self._signature = OctetString(signature)
        self._salt = OctetString(salt)

    @property
    def engineID(self) -> bytes:
        return self._engineID.data

    @property
    def engineBoots(self) -> int:
        return self._engineBoots.value

    @property
    def engineTime(self) -> int:
        return self._engineTime.value

    @property
    def userName(self) -> bytes:
        return self._userName.data

    @property
    def signature(self) -> subbytes:
        return self._signature.original

    @property
    def salt(self) -> bytes:
        return self._salt.data

    def __iter__(self) -> Iterator[ASN1]:
        yield self._engineID
        yield self._engineBoots
        yield self._engineTime
        yield self._userName
        yield self._signature
        yield self._salt

    def __len__(self) -> int:
        return 6

    def __repr__(self) -> str:
        args = (
            str(self.engineID),
            str(self.engineBoots),
            str(self.engineTime),
            str(self.userName),
            str(self.signature),
            str(self.salt),
        )

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Authoritative Engine ID: {self.engineID!r}",
            f"{subindent}Authoritative Engine Boots: {self.engineBoots}",
            f"{subindent}Authoritative Engine Time: {self.engineTime}",
            f"{subindent}User Name: {self.userName!r}",
            f"{subindent}Signature: {self.signature[:]!r}",
            f"{subindent}Encryption Salt: {self.salt!r}",
        ))

    @classmethod
    def deserialize(cls,
        data: Union[bytes, subbytes],
    ) -> "SignedUsmParameters":
        engineID, ptr   = OctetString.decode(data)
        engineBoots, ptr= Integer.decode(ptr)
        engineTime, ptr = Integer.decode(ptr)
        userName, ptr   = OctetString.decode(ptr)
        signature, ptr  = OctetString.decode(ptr, copy=False)
        salt            = OctetString.decodeExact(ptr)

        try:
            return cls(
                engineID.data,
                engineBoots.value,
                engineTime.value,
                userName.data,
                signature.original,
                salt.data,
            )
        except ValueError as err:
            raise ParseError(*err.args) from err
