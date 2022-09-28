__all__ = ["TransportDomain", "TransportListener"]

from abc import abstractmethod
from collections import namedtuple
import enum
import os

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

    @classmethod
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

supported = ("posix")
if os.name in supported:
    package = os.name
else:
    package = "generic"

package = "{}.{}".format(__name__, package)
