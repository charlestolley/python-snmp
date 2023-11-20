__all__ = [
    "AddressUsage", "TransportChannel", "TransportDomain",
    "TransportListener", "TransportMultiplexor"
]

from abc import abstractmethod
from collections import namedtuple
import enum
import os
import socket

from snmp.typing import *

AddressUsage = enum.Enum(
    "AddressUsage",
    ["LISTENER", "TRAP_LISTENER", "SENDER"]
)

class TransportDomain(enum.Enum):
    def __init__(self, family: socket.AddressFamily, loopback: str, default: str):
        self.address_family = family
        self.loopback_address = loopback
        self.default_address = default

    UDP_IPv4 = socket.AF_INET, "127.0.0.1", "0.0.0.0"
    UDP_IPv6 = socket.AF_INET6, "::1", "::"

T = TypeVar("T")
class Transport(Generic[T]):
    DOMAIN: ClassVar[TransportDomain]

    @classmethod
    @abstractmethod
    def normalizeAddress(cls,
        address: Any = None,
        usage: AddressUsage = None,
    ) -> T:
        ...

    @abstractmethod
    def close(self) -> None:
        ...

    @abstractmethod
    def send(self, address: T, data: bytes) -> None:
        ...

class TransportChannel:
    def __init__(self,
        transport: Transport[T],
        address: T,
        localAddress: T,
    ) -> None:
        self.localAddress = localAddress
        self.address = address
        self.transport = transport

    @property
    def domain(self) -> TransportDomain:
        return self.transport.DOMAIN

    def send(self, data: bytes) -> None:
        self.transport.send(self.address, data)

class TransportListener:
    @abstractmethod
    def hear(self, transport: Transport[T], address: T, data: bytes) -> None:
        ...

TransportType = TypeVar("TransportType", bound=Transport[Tuple[str, int]])
class TransportMultiplexor(Generic[TransportType]):
    @abstractmethod
    def register(self, sock: TransportType) -> None:
        ...

    @abstractmethod
    def listen(self, listener: TransportListener) -> None:
        ...

    @abstractmethod
    def stop(self) -> None:
        ...

    @abstractmethod
    def close(self) -> None:
        ...

supported = ("posix")
if os.name in supported:
    package = os.name
else:
    package = "generic"

package = "{}.{}".format(__name__, package)
