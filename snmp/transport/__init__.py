__all__ = ["TransportDomain"]

from collections import namedtuple
import enum
import os
from snmp.exception import IncompleteChildClass
from snmp.utils import typename

class Transport:
    class Listener:
        def hear(self, transport, address, data):
            pass

    @classmethod
    def Locator(cls, address):
        return TransportLocator(cls.DOMAIN, cls.normalizeAddress(address))

    @classmethod
    def normalizeAddress(cls, address):
        return address

    def close(self):
        pass

    def listen(self, listener):
        pass

    def send(self, address, data):
        errmsg = "{} does not implement send()".format(typename(self))
        raise IncompleteChildClass(errmsg)

    def stop(self):
        pass

TransportDomain = enum.Enum("TransportDomain", ("UDP",))
TransportLocator = namedtuple("TransportLocator", ("domain", "address"))

supported = ("nt", "posix")
if os.name in supported:
    package = os.name
else:
    from platform import platform
    raise ImportError("Unsupported platform: \"{}\"".format(platform()))

package = "{}.{}".format(__name__, package)
