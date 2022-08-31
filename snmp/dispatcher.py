__all__ = ["Dispatcher"]

import threading

from snmp.ber import ParseError, decode
from snmp.exception import *
from snmp.message import MessageProcessingModel
from snmp.security.levels import noAuthNoPriv
from snmp.transport import Transport, TransportDomain
from snmp.types import SEQUENCE, Integer
from snmp.utils import typename

class Dispatcher(Transport.Listener):
    class Handle:
        def addCallback(self, func, *args):
            errmsg = "{} does not support callbacks".format(typename(self))
            raise IncompleteChildClass(errmsg)

        def push(self, response):
            errmsg = "{} does not implement push()".format(typename(self))
            raise IncompleteChildClass(errmsg)

    def __init__(self):
        self.lock = threading.Lock()
        self.msgProcessors = {}
        self.threads = {}
        self.transports = {}

    def addMessageProcessor(self, mp):
        with self.lock:
            self.msgProcessors[mp.VERSION] = mp

    def connectTransport(self, transport):
        domain = transport.DOMAIN

        with self.lock:
            if domain in self.threads:
                if self.transports.get(domain) is transport:
                    return

                errmsg = "This {} instance is already connected to {}"
                raise ValueError(errmsg.format(typename(self), str(domain)))

            thread = threading.Thread(
                target=transport.listen,
                args=(self,))

            thread.start()

            self.transports[domain] = transport
            self.threads[domain] = thread

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
                message, handle = mp.prepareDataElements(message)
            except IncomingMessageError:
                return

            handle.push(message)
        except AssertionError:
            pass
        except Exception:
            pass

    def sendPdu(self, locator, mpm, pdu, handle, *args, **kwargs):
        with self.lock:
            try:
                transport = self.transports[locator.domain]
            except KeyError as err:
                domain = str(TransportDomain(locator.domain))
                raise ValueError("{} is not enabled".format(domain)) from err

            try:
                mp = self.msgProcessors[mpm]
            except KeyError as err:
                mpm = str(MessageProcessingModel(mpm))
                raise ValueError("{} is not enabled".format(mpm)) from err

        msg = mp.prepareOutgoingMessage(pdu, handle, *args, **kwargs)
        transport.send(locator.address, msg)
        return handle

    def shutdown(self):
        with self.lock:
            for transport in self.transports.values():
                transport.stop()

            for thread in self.threads.values():
                thread.join()

            for transport in self.transports.values():
                transport.close()

            self.transports.clear()
            self.threads.clear()
