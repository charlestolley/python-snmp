__all__ = ["VersionDecoder"]

import weakref
from snmp.message import *

class VersionDecoder:
    def __init__(self):
        self.listeners = weakref.WeakValueDictionary()

    def hear(self, transport, address, data):
        msgVersion = VersionOnlyMessage.decode(data).version

        try:
            listener = self.listeners[msgVersion]
        except KeyError as err:
            raise BadVersion() from err
        else:
            listener.hear(transport, address, data)

    def register(self, version, listener):
        registered = self.listeners.setdefault(version, listener)
        return registered is listener
