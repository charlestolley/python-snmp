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
        self.engineID = engineID
        self.engineBoots = engineBoots
        self.engineTime = engineTime
        self.userName = userName
        self.padding = padding
        self.salt = salt

    def __iter__(self) -> Iterator[ASN1]:
        yield OctetString(self.engineID)
        yield Integer(self.engineBoots)
        yield Integer(self.engineTime)
        yield OctetString(self.userName)
        yield OctetString(self.padding)
        yield OctetString(self.salt)

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

        return cls(
            engineID.data,
            engineBoots.value,
            engineTime.value,
            userName.data,
            padding.data,
            salt.data,
        )

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
        self.engineID = engineID
        self.engineBoots = engineBoots
        self.engineTime = engineTime
        self.userName = userName
        self.signature = signature
        self.salt = salt

    def __iter__(self) -> Iterator[ASN1]:
        yield OctetString(self.engineID)
        yield Integer(self.engineBoots)
        yield Integer(self.engineTime)
        yield OctetString(self.userName)
        yield OctetString(self.signature)
        yield OctetString(self.salt)

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

        return cls(
            engineID.data,
            engineBoots.value,
            engineTime.value,
            userName.data,
            signature.original,
            salt.data,
        )
