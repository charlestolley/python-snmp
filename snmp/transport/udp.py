__all__ = [
    "UdpIPv4Socket", "UdpIPv6Socket",
    "UdpIPv4Transport", "UdpIPv6Transport",
]

import importlib
from socket import *

from snmp.transport import *
from snmp.transport import Transport, package
from snmp.typing import *

class UdpSocket(Transport[Tuple[str, int]]):
    DOMAIN = ClassVar[TransportDomain]
    DEFAULT_PORT: ClassVar[int] = 161

    @classmethod
    def normalizeAddress(cls, address: Any) -> Tuple[str, int]:
        if isinstance(address, tuple):
            addr, port = address
        else:
            addr = address
            port = cls.DEFAULT_PORT

        try:
            _ = inet_pton(cls.DOMAIN.address_family, addr)
        except OSError as err:
            family = cls.DOMAIN.address_family.name
            errstr = f"Invalid address for {family}: \"{addr}\""
            raise ValueError(errstr) from err
        except TypeError as err:
            raise TypeError(f"Address must be a str: {addr}") from err

        if port <= 0 or port > 0xffff:
            errmsg = "Invalid UDP port number: {}"
            raise ValueError(errmsg.format(port))

        return addr, port

    def __init__(self, host: str = "", port = 0) -> None:
        self.socket = socket(self.DOMAIN.address_family, SOCK_DGRAM)
        self.socket.setblocking(False)
        self.socket.bind((host, port))

    def send(self, address: Tuple[str, int], data: bytes) -> None:
        self.socket.sendto(data, addr)

    def close(self) -> None:
        self.socket.close()

class UdpIPv4Socket(UdpSocket):
    DOMAIN = TransportDomain.UDP_IPv4

class UdpIPv6Socket(UdpSocket):
    DOMAIN = TransportDomain.UDP_IPv6

module = importlib.import_module(".udp", package=package)
UdpIPv4Transport = module.UdpIPv4Transport
UdpIPv6Transport = module.UdpIPv6Transport
UdpIPv4Transport.DOMAIN = TransportDomain.UDP_IPv4
UdpIPv6Transport.DOMAIN = TransportDomain.UDP_IPv6
