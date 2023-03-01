__all__ = ["Dispatcher"]

import threading

from abc import abstractmethod
from snmp.ber import ParseError, decode
from snmp.exception import *
from snmp.message import *
from snmp.security.levels import noAuthNoPriv
from snmp.transport import *
from snmp.types import SEQUENCE, Integer
from snmp.utils import typename

class Dispatcher(TransportListener):
    def __init__(self, multiplexor):
        self.lock = threading.Lock()
        self.msgProcessors = {}
        self.transports = {}

        self.multiplexor = multiplexor
        self.thread = None

    def addMessageProcessor(self, mp):
        with self.lock:
            self.msgProcessors[mp.VERSION] = mp

    def connectTransport(self, transport):
        domain = transport.DOMAIN

        with self.lock:
            if domain in self.transports:
                if self.transports.get(domain) is transport:
                    return

                errmsg = "This {} instance is already connected to {}"
                raise ValueError(errmsg.format(typename(self), str(domain)))

            if self.thread is not None:
                self.multiplexor.stop()
                self.thread.join()

            self.multiplexor.register(transport)
            self.thread = threading.Thread(
                target=self.multiplexor.listen,
                args=(self,)
            )

            self.thread.start()
            self.transports[domain] = transport

    def hear(self, transport, address, data):
        try:
            try:
                msgVersion, message = MessageBase.decodeVersion(data)
            except ParseError:
                return

            with self.lock:
                try:
                    mp = self.msgProcessors[msgVersion]
                except KeyError:
                    return

            try:
                message, handle = mp.prepareDataElements(message)
                handle.push(message)
            except IncomingMessageError:
                return

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

    def shutdown(self):
        with self.lock:
            if self.thread is not None:
                self.multiplexor.stop()
                self.thread.join()

            self.multiplexor.close()
            self.thread = None
