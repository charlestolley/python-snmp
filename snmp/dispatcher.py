import threading
from snmp.ber import decode
from snmp.security.levels import noAuthNoPriv
from snmp.types import SEQUENCE, Integer

class BadVersion(ValueError):
    pass

class Handle:
    def __init__(self):
        self.event = threading.Event()
        self.response = None

    def signal(self):
        self.event.set()

    def wait(self):
        self.event.wait()

class Dispatcher:
    def __init__(self, preparer):
        self.preparer = preparer

    def enableTransport(self, transportType):
        self.transport = transportType(self)
        return self.transport

    def hear(self, sender, data):
        message = decode(data, expected=SEQUENCE, copy=False)
        msgVersion, message = Integer.decode(message, leftovers=True)

        if msgVersion.value != self.preparer.VERSION:
            raise BadVersion(msgVersion.value)

        response, handle = self.preparer.prepareDataElements(message)
        handle.response = response
        handle.signal()

    def sendPdu(self, address, pdu, *args, **kwargs):
        handle = Handle()
        msg = self.preparer.prepareOutgoingMessage(pdu, handle, *args, **kwargs)
        self.transport.send(address, msg)
        return handle

    def activate(self):
        self.thread = threading.Thread(target=self.transport.listen)
        self.thread.start()

    def shutdown(self):
        self.transport.stop()
        self.thread.join()
