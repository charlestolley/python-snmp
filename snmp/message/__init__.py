__all__ = [
    "Message", "MessageBase", "MessageProcessor",
    "MessageProcessingModel", "RequestHandle",
]

from abc import abstractmethod
import enum

from snmp.ber import *
from snmp.pdu import *
from snmp.types import *
from snmp.typing import *
from snmp.utils import *

T = TypeVar("T")
TPDU = TypeVar("TPDU", bound=AnyPDU)
TMessage = TypeVar("TMessage", bound="Message")
TMessageBase = TypeVar("TMessageBase", bound="MessageBase")

class MessageProcessingModel(enum.IntEnum):
    SNMPv1  = 0
    SNMPv2c = 1
    SNMPv3  = 3

class MessageBase(Sequence):
    @staticmethod
    def decodeVersion(data: Asn1Data) -> Tuple[int, subbytes]:
        ptr = decode(data, expected=SEQUENCE, leftovers=False, copy=False)
        version, ptr = Integer.decode(ptr, leftovers=True)
        return version.value, ptr

    @classmethod
    @abstractmethod
    def decodeBody(cls: Type[TMessageBase],
        data: subbytes,
        types: Optional[Mapping[Identifier, Type[AnyPDU]]],
        version: MessageProcessingModel = MessageProcessingModel.SNMPv1,
    ) -> TMessageBase:
        ...

    @classmethod
    def deserialize(cls: Type[TMessageBase], # type: ignore[override]
        data: Asn1Data,
        types: Optional[Mapping[Identifier, Type[AnyPDU]]],
    ) -> TMessageBase:
        version, ptr = cls.decodeVersion(data)
        return cls.decodeBody(ptr, types, MessageProcessingModel(version))

class Message(MessageBase):
    def __init__(self,
        version: MessageProcessingModel,
        community: bytes,
        pdu: AnyPDU,
    ) -> None:
        self.version = version
        self.community = community
        self.pdu = pdu

    def __iter__(self) -> Iterator[Asn1Encodable]:
        yield Integer(self.version)
        yield OctetString(self.community)
        yield self.pdu

    def __len__(self) -> int:
        return 3

    def __repr__(self) -> str:
        return f"{typename(self)}({self.community!r}, {repr(self.pdu)})"

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
    def decodeBody(cls: Type[TMessage],
        data: Asn1Data,
        types: Optional[Mapping[Identifier, Type[AnyPDU]]],
        version: MessageProcessingModel = MessageProcessingModel.SNMPv1,
    ) -> TMessage:
        if types is None:
            types = dict()

        community, data = OctetString.decode(data, leftovers=True)
        identifier = Identifier.decode(subbytes(data))

        try:
            pduType = types[identifier]
        except KeyError as err:
            raise ParseError(f"Invalid PDU type: {identifier}") from err

        return cls(version, cast(bytes, community.data), pduType.decode(data))

class RequestHandle(Generic[T]):
    @abstractmethod
    def addCallback(self, func: Callable[[int], None], idNum: int) -> None:
        ...

    @abstractmethod
    def push(self, response: T) -> None:
        ...

class MessageProcessor(Generic[T, TPDU]):
    VERSION: ClassVar[MessageProcessingModel]

    @abstractmethod
    def prepareDataElements(self, msg: subbytes) -> Tuple[T, RequestHandle[T]]:
        ...

    @abstractmethod
    def prepareOutgoingMessage(self,
        pdu: TPDU,
        handle: RequestHandle[T],
        *args: Any,
        **kwargs: Any,
    ) -> bytes:
        ...
