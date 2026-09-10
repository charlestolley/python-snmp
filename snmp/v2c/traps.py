__all__ = ["SNMPv2cTrapDecoder"]

import logging

class SNMPv2cTrapDecoder:
    def __init__(self):
        self.handler = None
        self.logger = logging.getLogger(__name__.split(".")[0])

    def hear(self, message, channel):
        vblist = message.pdu.variableBindings
        kwargs = {
            "address": channel.address,
            "version": message.version,
            "domain": channel.transport.DOMAIN,
            "community": message.community,
        }

        try:
            self.handler.trap(vblist, **kwargs)
        except Exception as exc:
            self.logger.exception(exc)

    def setHandler(self, handler):
        self.handler = handler
