from snmp.dispatcher import *
from snmp.manager.v1 import *
from snmp.manager.v2c import *
from snmp.manager.v3 import *
from snmp.message import *
from snmp.message.v1 import SNMPv1MessageProcessor
from snmp.message.v2c import SNMPv2cMessageProcessor
from snmp.message.v3 import SNMPv3MessageProcessor
from snmp.security import *
from snmp.security.usm import *
from snmp.transport import *
from snmp.transport.udp import *

class Engine:
    TRANSPORTS = {
        cls.DOMAIN: cls for cls in [
            UdpIPv4Socket,
            UdpIPv6Socket,
        ]
    }

    def __init__(self,
        defaultVersion=MessageProcessingModel.SNMPv3,
        defaultDomain=TransportDomain.UDP_IPv4,
        defaultSecurityModel=SecurityModel.USM,
        defaultCommunity=b"",
        msgMaxSize=None,
        autowait=True,
    ):
        # Read-only variables
        self.defaultVersion         = defaultVersion
        self.defaultDomain          = defaultDomain
        self.defaultSecurityModel   = defaultSecurityModel
        self.defaultCommunity       = defaultCommunity
        self.autowaitDefault        = autowait

        if msgMaxSize is None:
            multiplexor = UdpMultiplexor()
        else:
            multiplexor = UdpMultiplexor(msgMaxSize)

        self.dispatcher = Dispatcher(multiplexor)
        self.transports = set()

        self.mpv1 = None
        self.mpv2c = None
        self.mpv3 = None
        self._usm = None

    @property
    def usm(self):
        if self._usm is None:
            self._usm = UserBasedSecurityModule()
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

    def v1Manager(self, locator, autowait, community=None):
        if community is None:
            community = self.defaultCommunity

        if self.mpv1 is None:
            self.mpv1 = SNMPv1MessageProcessor()
            self.dispatcher.addMessageProcessor(self.mpv1)

        return SNMPv1Manager(
            self.dispatcher,
            locator,
            community,
            autowait,
        )

    def v2cManager(self, locator, autowait, community=None):
        if community is None:
            community = self.defaultCommunity

        if self.mpv2c is None:
            self.mpv2c = SNMPv2cMessageProcessor()
            self.dispatcher.addMessageProcessor(self.mpv2c)

        return SNMPv2cManager(
            self.dispatcher,
            locator,
            community,
            autowait,
        )

    def v3Manager(self, locator, autowait, engineID=None,
            securityModel=None, defaultSecurityLevel=None, **kwargs):
        if securityModel is None:
            securityModel = self.defaultSecurityModel
        elif not isinstance(securityModel, SecurityModel):
            securityModel = SecurityModel(securityModel)

        if self.mpv3 is None:
            self.mpv3 = SNMPv3MessageProcessor()
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

            self.mpv3.addSecurityModuleIfNeeded(self.usm)

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

    def Manager(self, address, version=None,
                domain=None, autowait=None, **kwargs):
        if domain is None:
            domain = self.defaultDomain

        if autowait is None:
            autowait = self.autowaitDefault

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
