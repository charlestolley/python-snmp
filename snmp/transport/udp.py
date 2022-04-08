__all__ = ["UdpTransport"]

import importlib
from socket import AF_INET, inet_pton
from . import Transport, TransportDomain, package

class UdpTransportBase(Transport):
    DEFAULT_PORT = 161

    @staticmethod
    def normalizeAddress(address):
        if isinstance(address, tuple):
            ip, port = address
        else:
            ip = address
            port = UdpTransportBase.DEFAULT_PORT

        try:
            inet_pton(AF_INET, ip)
        except OSError as err:
            raise ValueError("Invalid IPv4 address: {}".format(ip)) from err

        if port <= 0 or port > 0xffff:
            errmsg = "Invalid UDP port number: {}"
            raise ValueError(errmsg.format(port)) from err

        return ip, port

module = importlib.import_module(".udp", package=package)
UdpTransport = module.UdpTransport
UdpTransport.DOMAIN = TransportDomain.UDP
