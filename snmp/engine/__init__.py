from snmp.dispatcher import *
from snmp.engine.usm import *
from snmp.manager.v1 import *
from snmp.manager.v2c import *
from snmp.manager.v3 import *
from snmp.message import *
import snmp.message.v1
import snmp.message.v2c
import snmp.message.v3
from snmp.security import *
from snmp.transport import *
from snmp.transport.udp import *

class Engine:
    TRANSPORTS = {
        cls.DOMAIN: cls for cls in [
            UdpTransport,
        ]
    }

    def __init__(self,
        defaultVersion=MessageProcessingModel.SNMPv3,
        defaultDomain=TransportDomain.UDP,
        defaultSecurityModel=SecurityModel.USM,
        autowait=True
    ):
        # Read-only variables
        self.defaultVersion         = defaultVersion
        self.defaultDomain          = defaultDomain
        self.defaultSecurityModel   = defaultSecurityModel
        self.autowaitDefault        = autowait

        self.dispatcher = Dispatcher()
        self.transports = set()

        self.mpv1 = None
        self.mpv2c = None
        self.mpv3 = None
        self._usm = None

    @property
    def usm(self):
        if self._usm is None:
            self._usm = UsmControlModule()
        return self._usm

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.shutdown()

    def shutdown(self):
        self.dispatcher.shutdown()

    def connectTransport(self, transport):
        if transport.DOMAIN in self.transports:
            errmsg = "{} is already handled by a different transport object"
            raise ValueError(errmsg.format(transport.DOMAIN))
        elif transport.DOMAIN not in self.TRANSPORTS:
            errmsg = f"Unsupported transport domain: {transport.DOMAIN}"
            raise ValueError(errmsg)

        self.dispatcher.connectTransport(transport)
        self.transports.add(transport.DOMAIN)

    def v1Manager(self, locator, autowait, community=b""):
        if self.mpv1 is None:
            self.mpv1 = snmp.message.v1.MessageProcessor()
            self.dispatcher.addMessageProcessor(self.mpv1)

        return SNMPv1Manager(self.dispatcher, locator, community, autowait)

    def v2cManager(self, locator, autowait, community=""):
        if self.mpv2c is None:
            self.mpv2c = snmp.message.v2c.MessageProcessor()
            self.dispatcher.addMessageProcessor(self.mpv2c)

        return SNMPv2cManager(self.dispatcher, locator, community, autowait)

    def v3Manager(self, locator, autowait, securityModel=None,
            engineID=None, defaultSecurityLevel=None, **kwargs):
        if securityModel is None:
            securityModel = self.defaultSecurityModel
        elif not isinstance(securityModel, SecurityModel):
            securityModel = SecurityModel(securityModel)

        if self.mpv3 is None:
            self.mpv3 = snmp.message.v3.MessageProcessor()
            self.dispatcher.addMessageProcessor(self.mpv3)

        if securityModel == SecurityModel.USM:
            defaultUserName = kwargs.get("defaultUserName")
            namespace = kwargs.get("namespace", "")

            if defaultUserName is None:
                defaultUserName = self.usm.getDefaultUser(namespace)

            if defaultSecurityLevel is None:
                defaultSecurityLevel = self.usm.getDefaultSecurityLevel(
                    defaultUserName,
                    namespace,
                )

            self.mpv3.addSecurityModuleIfNeeded(self.usm.securityModule)

            return SNMPv3UsmManager(
                self.dispatcher,
                self.usm,
                locator,
                namespace,
                defaultUserName.encode(),
                defaultSecurityLevel,
                engineID=engineID,
                autowait=autowait,
            )
        else:
            errmsg = f"Unsupported security model: {str(securityModel)}"
            raise ValueError(errmsg)

    def Manager(self, address, domain=None,
                version=None, autowait=None, **kwargs):
        if autowait is None:
            autowait = self.autowaitDefault

        if domain is None:
            domain = self.defaultDomain

        try:
            locator = self.TRANSPORTS[domain].Locator(address)
        except KeyError as err:
            errmsg = f"Unsupported transport domain: {domain}"
            raise ValueError(errmsg) from err

        if locator.domain not in self.transports:
            transportClass = self.TRANSPORTS[locator.domain]
            self.dispatcher.connectTransport(transportClass())
            self.transports.add(locator.domain)

        if version is None:
            version = self.defaultVersion
        elif not isinstance(version, MessageProcessingModel):
            version = MessageProcessingModel(version)

        if version == MessageProcessingModel.SNMPv3:
            return self.v3Manager(locator, autowait, **kwargs)
        elif version == MessageProcessingModel.SNMPv2c:
            return self.v2cManager(locator, autowait, **kwargs)
        elif version == MessageProcessingModel.SNMPv1:
            return self.v1Manager(locator, autowait, **kwargs)
        else:
            raise ValueError(f"Unsupported protocol version: {str(version)}")