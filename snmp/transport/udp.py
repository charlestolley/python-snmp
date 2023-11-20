__all__ = [
    "UdpIPv4Socket", "UdpIPv6Socket", "UdpMultiplexor",
]

import importlib
from socket import *

from snmp.transport import *
from snmp.transport import Transport, package
from snmp.typing import *

class UdpSocket(Transport[Tuple[str, int]]):
    DOMAIN: ClassVar[TransportDomain]

    DEFAULT_PORT: ClassVar[Mapping[AddressUsage, int]] = {
        AddressUsage.LISTENER: 161,
        AddressUsage.SENDER: 0,
        AddressUsage.TRAP_LISTENER: 162,
    }

    @classmethod
    def normalizeAddress(cls,
        address: Any = None,
        usage: Optional[AddressUsage] = None,
    ) -> Tuple[str, int]:
        if isinstance(address, tuple):
            addr, port = address
        else:
            if address is None:
                addr = cls.DOMAIN.default_address
            else:
                addr = address

            if usage is None:
                port = 0
            else:
                port = cls.DEFAULT_PORT[usage]

        permissive = usage not in (
            AddressUsage.LISTENER,
            AddressUsage.TRAP_LISTENER,
        )

        if addr == "" and permissive:
            addr = cls.DOMAIN.default_address

        try:
            _ = inet_pton(cls.DOMAIN.address_family, addr)
        except OSError as err:
            family = cls.DOMAIN.address_family.name
            errstr = f"Invalid address for {family}: \"{addr}\""
            raise ValueError(errstr) from err
        except TypeError as err:
            raise TypeError(f"Address must be a str: {addr}") from err

        if port < 0 or port > 0xffff or (port == 0 and not permissive):
            errmsg = "Invalid UDP port number: {}"
            raise ValueError(errmsg.format(port))

        return addr, port

    @property
    def fileno(self) -> int:
        return self.socket.fileno()

    @property
    def port(self) -> int:
        return cast(int, self.socket.getsockname()[1])

    def __init__(self, host: str = "", port: int = 0) -> None:
        self.socket = socket(self.DOMAIN.address_family, SOCK_DGRAM)
        self.socket.setblocking(False)
        self.socket.bind((host, port))

    def receive(self, size: int) -> Tuple[Tuple[str, int], bytes]:
        data, addr = self.socket.recvfrom(size)
        return addr, data

    def send(self, address: Tuple[str, int], data: bytes) -> None:
        self.socket.sendto(data, address)

    def close(self) -> None:
        self.socket.close()

class UdpIPv4Socket(UdpSocket):
    DOMAIN = TransportDomain.UDP_IPv4

class UdpIPv6Socket(UdpSocket):
    DOMAIN = TransportDomain.UDP_IPv6

module = importlib.import_module(".udp", package=package)
UdpMultiplexor = module.UdpMultiplexor
