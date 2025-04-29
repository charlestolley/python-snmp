__all__ = ["Dispatcher", "ListenThread"]

import threading

from snmp.ber import ParseError
from snmp.exception import *
from snmp.message import *
from snmp.pdu import AnyPDU
from snmp.transport import *
from snmp.typing import *
from snmp.utils import typename

class ListenThread:
    def __init__(self, multiplexor):
        self.multiplexor = multiplexor
        self.thread = None

    def connectTransport(self, transport, listener) -> None:
        domain = transport.DOMAIN

        if self.thread is not None:
            self.multiplexor.stop()
            self.thread.join()

        self.multiplexor.register(transport, listener)
        self.thread = threading.Thread(
            target=self.multiplexor.listen,
        )

        self.thread.start()

    def shutdown(self) -> None:
        if self.thread is not None:
            self.multiplexor.stop()
            self.thread.join()

        self.multiplexor.close()
        self.thread = None

class Dispatcher(TransportListener):
    def __init__(self):
        self.lock = threading.Lock()
        self.msgProcessors = {}

    def addMessageProcessor(self, mp):
        with self.lock:
            self.msgProcessors[mp.VERSION] = mp

    def hear(self, transport, address, data):
        try:
            try:
                msgVersion = VersionOnlyMessage.decodeExact(data).version
            except BadVersion:
                return
            except ParseError:
                return

            with self.lock:
                try:
                    mp = self.msgProcessors[msgVersion]
                except KeyError:
                    return

            try:
                message, handle = mp.prepareDataElements(data)
                handle.push(message)
            except IncomingMessageError:
                return

        except AssertionError:
            pass
        except Exception:
            pass

    def sendPdu(self, channel, msgVersion, pdu, handle, *args, **kwargs):
        with self.lock:
            try:
                mp = self.msgProcessors[msgVersion]
            except KeyError as err:
                version = str(ProtocolVersion(msgVersion))
                raise ValueError("{} is not enabled".format(version)) from err

        msg = mp.prepareOutgoingMessage(pdu, handle, *args, **kwargs)
        channel.send(msg)
