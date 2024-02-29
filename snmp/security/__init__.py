__all__ = ["SecurityLevel", "SecurityModel", "SecurityModule"]

from snmp.smi import Sequence
from snmp.typing import *

from .levels import SecurityLevel
from .models import SecurityModel

TMessage = TypeVar("TMessage", bound="Sequence")

class SecurityModule(Generic[TMessage]):
    MODEL: ClassVar[SecurityModel]

    def processIncoming(self,
        message: TMessage,
        timestamp: Optional[float] = None,
    ) -> None:
        raise NotImplementedError()

    def prepareOutgoing(self,
        message: TMessage,
        engineID: bytes,
        securityName: bytes,
    ) -> bytes:
        raise NotImplementedError()
