__all__ = ["UdpIPv4Transport", "UdpIPv6Transport"]

import importlib
from socket import inet_pton

from snmp.transport import *
from snmp.transport import Transport, package
from snmp.typing import *

class UdpTransport(Transport[Tuple[str, int]]):
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

module = importlib.import_module(".udp", package=package)
UdpIPv4Transport = module.UdpIPv4Transport
UdpIPv6Transport = module.UdpIPv6Transport
UdpIPv4Transport.DOMAIN = TransportDomain.UDP_IPv4
UdpIPv6Transport.DOMAIN = TransportDomain.UDP_IPv6
