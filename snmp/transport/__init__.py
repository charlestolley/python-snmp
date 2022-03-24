import enum
import os
from snmp.exception import IncompleteChildClass

class Transport:
    class Listener:
        def hear(self, transport, address, data):
            pass

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

if os.name == "posix":
    package = "posix"
else:
    from platform import platform
    raise ImportError("Unsupported platform: \"{}\"".format(platform()))

package = "{}.{}".format(__name__, package)
