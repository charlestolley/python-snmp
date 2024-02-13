__all__ = [
    "BadVersion", "ProtocolVersion",
    "VersionOnlyMessage", "Message",
    "RequestHandle", "MessageProcessor",
]

import enum

from snmp.asn1 import *
from snmp.ber import *
from snmp.exception import *
from snmp.pdu import *
from snmp.smi import *
from snmp.typing import *
from snmp.utils import *

T = TypeVar("T")
TPDU = TypeVar("TPDU", bound=AnyPDU)
TMessage = TypeVar("TMessage", bound="Message")

@final
class BadVersion(IncomingMessageError):
    pass

class ProtocolVersion(enum.IntEnum):
    SNMPv1  = 0
    SNMPv2c = 1
    SNMPv3  = 3

    # Python 3.11 changes IntEnum.__str__()
    __str__ = enum.Enum.__str__

@final
class VersionOnlyMessage(Sequence):
    def __init__(self, version: ProtocolVersion) -> None:
        self.version = version

    def __iter__(self) -> Iterator[ASN1]:
        yield Integer(self.version)

    def __len__(self) -> int:
        return 1

    def __repr__(self) -> str:
        return f"{typename(self)}({str(self.version)})"

    @classmethod
    def deserialize(cls,
        data: Asn1Data,
    ) -> "VersionOnlyMessage":
        msgVersion, _ = cast(
            Tuple[Integer, subbytes],
            Integer.decode(data, leftovers=True),
        )

        try:
            version = ProtocolVersion(msgVersion.value)
        except ValueError as err:
            raise BadVersion(msgVersion.value) from err

        return cls(version)

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
            Integer.decode(data, leftovers=True),
        )

        try:
            version = ProtocolVersion(msgVersion.value)
        except ValueError as err:
            raise BadVersion(msgVersion.value) from err

        if version not in cls.VERSIONS:
            raise BadVersion(f"{typename} does not support {version.name}")

        community, ptr = cast(
            Tuple[OctetString, subbytes],
            OctetString.decode(ptr, leftovers=True),
        )

        identifier, _ = Tag.decode(subbytes(ptr))

        if types is None:
            types = dict()

        try:
            pduType = types[identifier]
        except KeyError as err:
            raise ParseError(f"Invalid PDU type: {identifier}") from err

        return cls(
            version,
            community.data,
            cast(AnyPDU, pduType.decode(ptr)),
        )

class RequestHandle(Generic[T]):
    def addCallback(self, func: Callable[[int], None], idNum: int) -> None:
        raise NotImplementedError()

    def push(self, response: T) -> None:
        raise NotImplementedError()

class MessageProcessor(Generic[T, TPDU]):
    VERSION: ClassVar[ProtocolVersion]

    def prepareDataElements(self, msg: Asn1Data) -> Tuple[T, RequestHandle[T]]:
        raise NotImplementedError()

    def prepareOutgoingMessage(self,
        pdu: TPDU,
        handle: RequestHandle[T],
        *args: Any,
        **kwargs: Any,
    ) -> bytes:
        raise NotImplementedError()
