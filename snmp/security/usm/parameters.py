__all__ = ["UsmSecurityParameters"]

from snmp.asn1 import ASN1
from snmp.ber import *
from snmp.exception import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *

class UsmSecurityParameters(Sequence):
    def __init__(self,
        engineID: bytes,
        engineBoots: int,
        engineTime: int,
        userName: bytes,
        signature: Asn1Data,
        salt: bytes,
    ):
        self.engineID = engineID
        self.engineBoots = engineBoots
        self.engineTime = engineTime
        self.userName = userName
        self.salt = salt

        self.signature: bytes
        self.signatureIndex: Optional[int]
        self.wholeMsg: Optional[bytes]

        if isinstance(signature, subbytes):
            self.signature = signature[:]
            self.signatureIndex = signature.start
            self.wholeMsg = signature.data
        else:
            self.signature = signature
            self.signatureIndex = None
            self.wholeMsg = None

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
        signature: Asn1Data
        if self.wholeMsg is None:
            signature = self.signature
        else:
            if __debug__ and self.signatureIndex is None:
                errmsg = "wholeMsg is defined but signatureIndex is None"
                raise SNMPLibraryBug(errmsg)

            start = cast(int, self.signatureIndex)
            stop = start + len(self.signature)
            signature = subbytes(self.wholeMsg, start, stop)

        args = (
            str(self.engineID),
            str(self.engineBoots),
            str(self.engineTime),
            str(self.userName),
            str(signature),
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
            f"{subindent}Signature: {self.signature!r}",
            f"{subindent}Encryption Salt: {self.salt!r}",
        ))

    @overload
    @classmethod
    def decode(cls,
        data: Asn1Data,
    ) -> "UsmSecurityParameters":
        ...

    @overload
    @classmethod
    def decode(cls,
        data: Asn1Data,
        leftovers: bool = False,
        copy: bool = True,
        **kwargs: Any,
    ) -> Union[
        "UsmSecurityParameters",
        Tuple["UsmSecurityParameters", subbytes],
    ]:
        ...

    @classmethod
    def decode(cls,
        data: Asn1Data,
        leftovers: bool = False,
        copy: bool = False,
        **kwargs: Any,
    ) -> Union[
        "UsmSecurityParameters",
        Tuple["UsmSecurityParameters", subbytes],
    ]:
        return super().decode(data, leftovers, copy, **kwargs)

    @classmethod
    def deserialize(cls, data: Asn1Data) -> "UsmSecurityParameters":
        copy = not isinstance(data, subbytes)

        engineID, ptr = cast(
            Tuple[OctetString, subbytes],
            OctetString.decode(data, leftovers=True),
        )

        engineBoots, ptr = cast(
            Tuple[Integer, subbytes],
            Integer.decode(ptr, leftovers=True),
        )

        engineTime, ptr = cast(
            Tuple[Integer, subbytes],
            Integer.decode(ptr, leftovers=True),
        )

        userName, ptr = cast(
            Tuple[OctetString, subbytes],
            OctetString.decode(ptr, leftovers=True),
        )

        signature, ptr = cast(
            Tuple[OctetString, subbytes],
            OctetString.decode(ptr, leftovers=True, copy=copy),
        )

        salt = OctetString.decode(ptr)

        return cls(
            engineID.data,
            engineBoots.value,
            engineTime.value,
            userName.data,
            signature.original,
            salt.data,
        )

    @classmethod
    def findSignature(self, msgSecurityParameters: subbytes) -> subbytes:
        ptr = cast(
            subbytes,
            decode(msgSecurityParameters, Sequence.TAG, copy=False)
        )

        _, ptr = decode(ptr, OctetString.TAG,   leftovers=True, copy=False)
        _, ptr = decode(ptr, Integer.TAG,       leftovers=True, copy=False)
        _, ptr = decode(ptr, Integer.TAG,       leftovers=True, copy=False)
        _, ptr = decode(ptr, OctetString.TAG,   leftovers=True, copy=False)
        ptr, _ = decode(ptr, OctetString.TAG,   leftovers=True, copy=False)
        return ptr
