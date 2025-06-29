__all__ = ["Message"]

from snmp.asn1 import ASN1
from snmp.ber import Asn1Data, ParseError, Tag
from snmp.pdu import AnyPDU
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *

from .version import *

TMessage = TypeVar("TMessage", bound="Message")

class Message(Sequence):
    VERSIONS = (ProtocolVersion.SNMPv1, ProtocolVersion.SNMPv2c)

    def __init__(self,
        version: ProtocolVersion,
        community: bytes,
        pdu: AnyPDU,
    ) -> None:
        self.version = version
        self.community = community
        self.pdu = pdu

    def __iter__(self) -> Iterator[ASN1]:
        yield Integer(self.version)
        yield OctetString(self.community)
        yield self.pdu

    def __len__(self) -> int:
        return 3

    def __repr__(self) -> str:
        return "{}({}, {!r}, {})".format(
            typename(self),
            str(self.version),
            self.community,
            repr(self.pdu),
        )

    def __str__(self) -> str:
        return self.toString()

    def toString(self, depth: int = 0, tab: str = "    ") -> str:
        indent = tab * depth
        subindent = indent + tab
        return "\n".join((
            f"{indent}{typename(self)}:",
            f"{subindent}Community: {self.community!r}",
            f"{self.pdu.toString(depth+1, tab)}",
        ))

    @classmethod
    def deserialize(cls: Type[TMessage],
        data: Asn1Data,
        types: Optional[Mapping[Tag, Type[AnyPDU]]] = None,
    ) -> TMessage:
        msgVersion, ptr = cast(
            Tuple[Integer, subbytes],
            Integer.decode(data),
        )

        try:
            version = ProtocolVersion(msgVersion.value)
        except ValueError as err:
            raise ASN1.DeserializeError(err.args[0], BadVersion) from err

        if version not in cls.VERSIONS:
            errmsg = f"{typename(cls)} does not support {version.name}"
            raise ASN1.DeserializeError(errmsg, BadVersion)

        community, ptr = OctetString.decode(ptr)
        tag, _ = Tag.decode(subbytes(ptr))

        if types is None:
            types = dict()

        try:
            pduType = types[tag]
        except KeyError as err:
            raise ParseError(f"Invalid PDU type: {tag}", ptr) from err

        return cls(
            version,
            community.data,
            pduType.decodeExact(ptr),
        )
