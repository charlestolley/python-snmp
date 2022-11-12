__all__ = ["TransportDomain", "TransportListener"]

from abc import abstractmethod
from collections import namedtuple
import enum
import os

from snmp.typing import *

TransportDomain = enum.Enum("TransportDomain", ("UDP",))

T = TypeVar("T")
class TransportLocator(Generic[T]):
    def __init__(self, domain: TransportDomain, address: T) -> None:
        self.domain = domain
        self.address = address

class Transport(Generic[T]):
    DOMAIN: ClassVar[TransportDomain]

    @classmethod
    def Locator(cls, address: T) -> TransportLocator[T]:
        return TransportLocator(cls.DOMAIN, cls.normalizeAddress(address))

    @classmethod
    @abstractmethod
    def normalizeAddress(cls, address: Any) -> T:
        ...

    @abstractmethod
    def close(self) -> None:
        ...

    @abstractmethod
    def listen(self, listener: "TransportListener") -> None:
        ...

    @abstractmethod
    def send(self, address: T, data: bytes) -> None:
        ...

    @abstractmethod
    def stop(self) -> None:
        ...

class TransportListener:
    @abstractmethod
    def hear(self, transport: Transport[T], address: T, data: bytes) -> None:
        ...

supported = ("posix")
if os.name in supported:
    package = os.name
else:
    package = "generic"

package = "{}.{}".format(__name__, package)
