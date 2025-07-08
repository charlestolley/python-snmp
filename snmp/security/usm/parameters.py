__all__ = ["SignedUsmParameters", "UnsignedUsmParameters"]

from snmp.asn1 import ASN1
from snmp.ber import *
from snmp.exception import *
from snmp.smi import *
from snmp.utils import *

class UnsignedUsmParameters(Sequence):
    def __init__(self,
        engineID,
        engineBoots,
        engineTime,
        userName,
        padding,
        salt,
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
    def engineID(self):
        return self._engineID.data

    @property
    def engineBoots(self):
        return self._engineBoots.value

    @property
    def engineTime(self):
        return self._engineTime.value

    @property
    def userName(self):
        return self._userName.data

    @property
    def padding(self):
        return self._padding.data

    @property
    def salt(self):
        return self._salt.data

    def __iter__(self):
        yield self._engineID
        yield self._engineBoots
        yield self._engineTime
        yield self._userName
        yield self._padding
        yield self._salt

    def __len__(self):
        return 6

    def __repr__(self):
        args = (
            str(self.engineID),
            str(self.engineBoots),
            str(self.engineTime),
            str(self.userName),
            str(self.padding),
            str(self.salt),
        )

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self):
        return self.toString()

    def toString(self, depth = 0, tab = "    "):
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
    def deserialize(cls, data):
        engineID, ebdata = OctetString.decode(data)
        engineBoots, etdata = Integer.decode(ebdata)

        if engineBoots.value < 0:
            errmsg = f"negative value for engineBoots: {engineBoots.value}"
            raise ParseError(errmsg, ebdata, etdata)

        engineTime, undata = Integer.decode(etdata)

        if engineTime.value < 0:
            errmsg = f"negative value for engineTime: {engineTime.value}"
            raise ParseError(errmsg, etdata, undata)

        userName, ptr = OctetString.decode(undata)

        if len(userName.data) > 32:
            errmsg = f"userName exceeds 32 characters: {userName.data!r}"
            raise ParseError(errmsg, undata, ptr)

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
            raise ASN1.DeserializeError(*err.args) from err

    @classmethod
    def findPadding(self, msgSecurityParameters):
        tag, ptr, tail          = decode(msgSecurityParameters)
        tag, engineID, ptr      = decode(ptr)
        tag, engineBoots, ptr   = decode(ptr)
        tag, engineTime, ptr    = decode(ptr)
        tag, userName, ptr      = decode(ptr)
        tag, ptr, tail          = decode(ptr)
        return ptr

class SignedUsmParameters(Sequence):
    def __init__(self,
        engineID,
        engineBoots,
        engineTime,
        userName,
        signature,
        salt,
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
    def engineID(self):
        return self._engineID.data

    @property
    def engineBoots(self):
        return self._engineBoots.value

    @property
    def engineTime(self):
        return self._engineTime.value

    @property
    def userName(self):
        return self._userName.data

    @property
    def signature(self):
        return self._signature.original

    @property
    def salt(self):
        return self._salt.data

    def __iter__(self):
        yield self._engineID
        yield self._engineBoots
        yield self._engineTime
        yield self._userName
        yield self._signature
        yield self._salt

    def __len__(self):
        return 6

    def __repr__(self):
        args = (
            str(self.engineID),
            str(self.engineBoots),
            str(self.engineTime),
            str(self.userName),
            repr(self.signature),
            str(self.salt),
        )

        return f"{typename(self)}({', '.join(args)})"

    def __str__(self):
        return self.toString()

    def toString(self, depth = 0, tab = "    "):
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
    def deserialize(cls, data):
        engineID, ebdata   = OctetString.decode(data)
        engineBoots, etdata = Integer.decode(ebdata)

        if engineBoots.value < 0:
            errmsg = f"negative value for engineBoots: {engineBoots.value}"
            raise ParseError(errmsg, ebdata, etdata)

        engineTime, undata = Integer.decode(etdata)

        if engineTime.value < 0:
            errmsg = f"negative value for engineTime: {engineTime.value}"
            raise ParseError(errmsg, etdata, undata)

        userName, ptr = OctetString.decode(undata)

        if len(userName.data) > 32:
            errmsg = f"userName exceeds 32 characters: {userName.data!r}"
            raise ParseError(errmsg, undata, ptr)

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
            raise ASN1.DeserializeError(*err.args) from err
