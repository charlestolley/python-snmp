__all__ = ["UdpTransport"]

import importlib
from socket import AF_INET, inet_pton

from snmp.transport import *
from snmp.transport import Transport, package
from snmp.typing import *

class UdpTransportBase(Transport[Tuple[str, int]]):
    DEFAULT_PORT: ClassVar[int] = 161

    @classmethod
    def normalizeAddress(cls, address: Any) -> Tuple[str, int]:
        if isinstance(address, tuple):
            ip, port = address
        else:
            ip = address
            port = cls.DEFAULT_PORT

        try:
            inet_pton(AF_INET, ip)
        except OSError as err:
            raise ValueError(f"Invalid IPv4 address: \"{ip}\"") from err
        except TypeError as err:
            raise TypeError(f"IPv4 address must be a str: {ip}") from err

        if port <= 0 or port > 0xffff:
            errmsg = "Invalid UDP port number: {}"
            raise ValueError(errmsg.format(port))

        return ip, port

module = importlib.import_module(".udp", package=package)
UdpTransport = module.UdpTransport
UdpTransport.DOMAIN = TransportDomain.UDP
