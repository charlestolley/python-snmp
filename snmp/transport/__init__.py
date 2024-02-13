__all__ = [
    "AddressUsage", "Transport", "TransportChannel",
    "TransportDomain", "TransportListener", "TransportMultiplexor"
]

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
    def normalizeAddress(cls,
        address: Any = None,
        usage: Optional[AddressUsage] = None,
    ) -> T:
        raise NotImplementedError()

    def close(self) -> None:
        raise NotImplementedError()

    def send(self, address: T, data: bytes) -> None:
        raise NotImplementedError()

class TransportChannel(Generic[T]):
    def __init__(self,
        transport: Transport[T],
        address: T,
        localAddress: T,
    ) -> None:
        self.transport = transport
        self.address = address
        self.localAddress = localAddress

    @property
    def domain(self) -> TransportDomain:
        return self.transport.DOMAIN

    def send(self, data: bytes) -> None:
        self.transport.send(self.address, data)

class TransportListener(Generic[T]):
    def hear(self, transport: Transport[T], address: T, data: bytes) -> None:
        raise NotImplementedError()

class TransportMultiplexor(Generic[T]):

    def register(self, sock: Transport[T]) -> None:
        raise NotImplementedError()

    def listen(self, listener: TransportListener[T]) -> None:
        raise NotImplementedError()

    def stop(self) -> None:
        raise NotImplementedError()

    def close(self) -> None:
        raise NotImplementedError()

supported = ("posix")
if os.name in supported:
    package = os.name
else:
    package = "generic"

package = "{}.{}".format(__name__, package)
