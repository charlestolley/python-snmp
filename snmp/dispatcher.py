__all__ = ["Dispatcher"]

from snmp.ber import ParseError
from snmp.exception import *
from snmp.message import *
from snmp.transport import *
from snmp.typing import *
from snmp.utils import typename

class Dispatcher(TransportListener):
    def __init__(self):
        self.msgProcessors = {}

    def addMessageProcessor(self, mp):
        self.msgProcessors[mp.VERSION] = mp

    def hear(self, transport, address, data):
        try:
            try:
                msgVersion = VersionOnlyMessage.decodeExact(data).version
            except BadVersion:
                return
            except ParseError:
                return

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
        try:
            mp = self.msgProcessors[msgVersion]
        except KeyError as err:
            version = str(ProtocolVersion(msgVersion))
            raise ValueError("{} is not enabled".format(version)) from err

        msg = mp.prepareOutgoingMessage(pdu, handle, *args, **kwargs)
        channel.send(msg)
