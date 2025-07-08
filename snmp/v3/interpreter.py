__all__ = ["SNMPv3Interpreter", "SNMPv3MessageSorter"]

import weakref

from snmp.ber import Tag
from snmp.smi import OID
from snmp.pdu import ReportPDU
from snmp.security import SecurityModel
from snmp.v3.message import ReportMessage

from .message import *

snmpUnknownPDUHandlersInstance = OID.parse("1.3.6.1.6.3.11.2.1.3")

class SNMPv3Interpreter:
    def __init__(self, usm):
        self.usm = usm

    def decode(self, data):
        message = SNMPv3WireMessage.decodeExact(data)
        return self.usm.processIncoming(message)

    def encode(self, message):
        return self.usm.prepareOutgoing(message)

    def makeReport(self, message, *varbinds):
        return SNMPv3Message(
            HeaderData(
                message.header.msgID,
                message.header.maxSize,
                MessageFlags(message.header.flags.securityLevel),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ReportPDU(
                    *varbinds,
                    requestID=message.scopedPDU.pdu.requestID,
                ),
                message.scopedPDU.contextEngineID,
                message.scopedPDU.contextName,
            ),
            message.securityEngineID,
            message.securityName,
        )

    def pduType(self, message):
        return type(message.scopedPDU.pdu)

class SNMPv3MessageSorter:
    def __init__(self, interpreter):
        self.interpreter = interpreter
        self.subscribers = weakref.WeakValueDictionary()

        self.unknownHandlers = 0

    def register(self, pduType, subscriber):
        subscribed = self.subscribers.setdefault(pduType.TAG, subscriber)
        return subscriber is subscribed

    def forward(self, message, channel):
        pduType = self.interpreter.pduType(message)

        try:
            subscriber = self.subscribers[pduType.TAG]
        except KeyError:
            if not pduType.RESPONSE_CLASS:
                self.unknownHandlers += 1
                if pduType.CONFIRMED_CLASS:
                    try:
                        reportMessage = self.interpreter.makeReport(
                            message,
                            VarBind(
                                snmpUnknownPDUHandlersInstance,
                                Counter32(self.unknownHandlers),
                            )
                        )

                        data = self.interpreter.encode(reportMessage)
                        channel.send(data)
                    except Exception:
                        pass
        else:
            subscriber.hear(message, channel)

    def hear(self, data, channel):
        try:
            message = self.interpreter.decode(data)
        except ReportMessage as report:
            self.send(report.message, channel)
        else:
            self.forward(message, channel)

    def send(self, message, channel):
        channel.send(self.interpreter.encode(message))
