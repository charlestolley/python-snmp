__all__ = ["SNMPv3TrapDecoder"]

import logging

from snmp.message import ProtocolVersion

class SNMPv3TrapDecoder:
    def __init__(self):
        self.handler = None
        self.logger = logging.getLogger(__name__.split(".")[0])

    def hear(self, message, channel):
        vblist = message.scopedPDU.pdu.variableBindings
        kwargs = {
            "engineID": message.scopedPDU.contextEngineID,
            "namespaces": message.securityName.namespaces,
            "address": channel.address,
            "version": ProtocolVersion.SNMPv3,
            "domain": channel.transport.DOMAIN,
            "user": message.securityName.userName.decode(),
            "securityLevel": message.header.flags.securityLevel,
            "context": message.scopedPDU.contextName,
        }

        try:
            self.handler.trap(vblist, **kwargs)
        except Exception as exc:
            self.logger.exception(exc)

    def setHandler(self, handler):
        self.handler = handler
