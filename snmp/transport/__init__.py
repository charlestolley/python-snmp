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

    def send(self, data: bytes, address: T) -> None:
        raise NotImplementedError()

class TransportChannel(Generic[T]):
    def __init__(self,
        transport: Transport[T],
        address: T,
    ) -> None:
        self.transport = transport
        self.address = address

    @property
    def domain(self) -> TransportDomain:
        return self.transport.DOMAIN

    @property
    def msgMaxSize(self) -> int:
        return self.transport.recvSize

    def send(self, data: bytes) -> None:
        self.transport.send(data, self.address)

class TransportListener(Generic[T]):
    def hear(self, data, channel):
        raise NotImplementedError()

class TransportMultiplexor(Generic[T]):
    def register(self,
        sock: Transport[T],
        listener: TransportListener[T],
    ) -> None:
        raise NotImplementedError()

    def listen(self) -> None:
        done = False
        while not done:
            done = self.poll()

    def poll(self, timeout: Optional[float] = None) -> bool:
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
