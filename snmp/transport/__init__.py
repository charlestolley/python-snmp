__all__ = ["TransportDomain", "TransportListener"]

from abc import abstractmethod
from collections import namedtuple
import enum
import os
import socket

from snmp.typing import *

class TransportDomain(enum.Enum):
    def __init__(self, family: socket.AddressFamily, loopback: str):
        self.address_family = family
        self.loopback_address = loopback

    UDP_IPv4 = socket.AF_INET, "127.0.0.1"
    UDP_IPv6 = socket.AF_INET6, "::1"

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
