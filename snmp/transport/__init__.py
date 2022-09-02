__all__ = ["TransportDomain", "TransportListener"]

from abc import abstractmethod
from collections import namedtuple
import enum
import os
from snmp.utils import typename

TransportDomain = enum.Enum("TransportDomain", ("UDP",))
TransportLocator = namedtuple("TransportLocator", ("domain", "address"))

class TransportListener:
    @abstractmethod
    def hear(self, transport, address, data):
        ...

class Transport:
    @classmethod
    def Locator(cls, address):
        return TransportLocator(cls.DOMAIN, cls.normalizeAddress(address))

    @staticmethod
    def normalizeAddress(cls, address):
        return address

    @abstractmethod
    def close(self):
        ...

    @abstractmethod
    def listen(self, listener):
        ...

    @abstractmethod
    def send(self, address, data):
        ...

    @abstractmethod
    def stop(self):
        ...

supported = ("nt", "posix")
if os.name in supported:
    package = os.name
else:
    from platform import platform
    raise ImportError("Unsupported platform: \"{}\"".format(platform()))

package = "{}.{}".format(__name__, package)
