__all__ = ["UdpTransport"]

import importlib
from . import package

module = importlib.import_module(".udp", package=package)
UdpTransport = module.UdpTransport
