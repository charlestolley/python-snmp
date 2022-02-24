import threading
from snmp.ber import ParseError, decode
from snmp.exception import *
from snmp.security.levels import noAuthNoPriv
from snmp.types import SEQUENCE, Integer

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
        try:
            try:
                message = decode(data, expected=SEQUENCE, copy=False)
                msgVersion, message = Integer.decode(message, leftovers=True)
            except ParseError:
                return

            if msgVersion.value != self.preparer.VERSION:
                return

            try:
                response, handle = self.preparer.prepareDataElements(message)
            except IncomingMessageError:
                return

            handle.response = response
            handle.signal()
        except SNMPLibraryBug:
            pass
        except Exception:
            pass

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
