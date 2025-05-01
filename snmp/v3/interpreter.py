__all__ = ["SNMPv3Interpreter"]

from snmp.ber import Tag
from snmp.pdu import AnyPDU, ReportPDU
from snmp.security import SecurityModel
from snmp.typing import Type

from .message import *

class SNMPv3Interpreter:
    def __init__(self, usm):
        self.usm = usm

    def decode(self, data: bytes) -> SNMPv3Message:
        message = SNMPv3WireMessage.decodeExact(data)
        return self.usm.processIncoming(message)

    def encode(self, message: SNMPv3Message) -> bytes:
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

    def pduType(self, message: SNMPv3Message) -> Type[AnyPDU]:
        return type(message.scopedPDU.pdu)
