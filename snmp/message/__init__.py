__all__ = [
    "ProtocolVersion", "VersionOnlyMessage",
    "Message", "RequestHandle", "MessageProcessor",
]

from snmp.ber import Asn1Data
from snmp.pdu import AnyPDU
from snmp.typing import *

from .core import *
from .version import *

T = TypeVar("T")
TPDU = TypeVar("TPDU", bound=AnyPDU)

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
