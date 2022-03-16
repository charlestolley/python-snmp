import threading
from snmp.ber import ParseError, decode
from snmp.exception import *
from snmp.message import MessageProcessingModel
from snmp.security.levels import noAuthNoPriv
from snmp.transport import TransportDomain
from snmp.types import SEQUENCE, Integer
from snmp.utils import DummyLock

class Handle:
    def __init__(self):
        self.event = threading.Event()
        self.response = None

    def signal(self):
        self.event.set()

    def wait(self):
        self.event.wait()

class Dispatcher:
    def __init__(self, lockType=DummyLock):
        self.lock = lockType()
        self.msgProcessors = {}
        self.threads = {}
        self.transports = {}

    def addMessageProcessor(self, mp):
        with self.lock:
            self.msgProcessors[mp.VERSION] = mp

    def connectTransport(self, transport):
        with self.lock:
            self.transports[transport.DOMAIN] = transport

    def hear(self, transport, address, data):
        try:
            try:
                message = decode(data, expected=SEQUENCE, copy=False)
                msgVersion, message = Integer.decode(message, leftovers=True)
            except ParseError:
                return

            with self.lock:
                try:
                    mp = self.msgProcessors[msgVersion.value]
                except KeyError:
                    return

            try:
                response, handle = mp.prepareDataElements(message)
            except IncomingMessageError:
                return

            handle.response = response
            handle.signal()
        except SNMPLibraryBug:
            pass
        except Exception:
            pass

    def sendPdu(self, domain, address, mpm, pdu, *args, **kwargs):
        with self.lock:
            try:
                transport = self.transports[domain]
            except KeyError as err:
                domain = str(TransportDomain(domain))
                raise ValueError("{} is not enabled".format(domain)) from err

            try:
                mp = self.msgProcessors[mpm]
            except KeyError as err:
                mpm = str(MessageProcessingModel(mpm))
                raise ValueError("{} is not enabled".format(mpm)) from err

        handle = Handle()
        msg = mp.prepareOutgoingMessage(pdu, handle, *args, **kwargs)
        transport.send(address, msg)
        return handle

    def activate(self):
        with self.lock:
            for domain, transport in self.transports.items():
                thread = threading.Thread(
                    target=transport.listen,
                    args=(self,))
                thread.start()
                self.threads[domain] = thread

    def shutdown(self):
        with self.lock:
            for domain in self.threads.keys():
                self.transports[domain].stop()

            for thread in self.threads.values():
                thread.join()
