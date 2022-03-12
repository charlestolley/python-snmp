__all__ = ["UdpTransport"]

import importlib
from . import TransportDomain, package

module = importlib.import_module(".udp", package=package)
UdpTransport = module.UdpTransport
UdpTransport.DOMAIN = TransportDomain.UDP
