from snmp.exception import *
from snmp.message import ProtocolVersion
from snmp.pdu import ReportPDU, ResponsePDU
from snmp.pipeline import *
from snmp.requests import RequestPoller
from snmp.scheduler import Scheduler
from snmp.security.levels import noAuthNoPriv
from snmp.security.usm import *
from snmp.transport import *
from snmp.transport.udp import *
from snmp.v1.manager import *
from snmp.v1.requests import *
from snmp.v2c.manager import *
from snmp.v2c.requests import *
from snmp.v3.interpreter import *
from snmp.v3.manager import *

class NoDefaultUser(SNMPException):
    pass

class GenericEngine:
    TRANSPORTS = {
        cls.DOMAIN: cls for cls in [
            UdpIPv4Socket,
            UdpIPv6Socket,
        ]
    }

    def __init__(self,
        multiplexor,
        scheduler,
        defaultVersion = ProtocolVersion.SNMPv3,
        defaultDomain = TransportDomain.UDP_IPv4,
        defaultCommunity = b"public",
        autowait = True,
        verboseLogging = False,
    ):
        self.defaultVersion         = defaultVersion
        self.defaultDomain          = defaultDomain
        self.defaultCommunity       = defaultCommunity
        self.autowaitDefault        = autowait

        self.multiplexor = multiplexor
        self.scheduler = scheduler

        self.v1_admin = SNMPv1RequestAdmin(self.scheduler)
        self.v2c_admin = SNMPv2cRequestAdmin(self.scheduler)

        self.usm = UserBasedSecurityModule()
        self.v3_sorter = SNMPv3MessageSorter(SNMPv3Interpreter(self.usm))
        self.v3_table = SNMPv3MessageTable()
        self.v3_sorter.register(ReportPDU, self.v3_table)
        self.v3_sorter.register(ResponsePDU, self.v3_table)

        self.decoder = VersionDecoder()
        self.pipeline = Catcher(self.decoder, verbose=verboseLogging)
        self.decoder.register(ProtocolVersion.SNMPv1, self.v1_admin)
        self.decoder.register(ProtocolVersion.SNMPv2c, self.v2c_admin)
        self.decoder.register(ProtocolVersion.SNMPv3, self.v3_sorter)

        self.transports = {}

    def __del__(self):
        self.multiplexor.close()

    def addUser(self,
        user,
        namespace = "",
        default = None,
        authProtocol = None,
        privProtocol = None,
        authSecret = None,
        privSecret = None,
        secret = None,
        defaultSecurityLevel = None,
    ):
        self.usm.addUser(
            user.encode(),
            namespace,
            default,
            authProtocol,
            privProtocol,
            authSecret,
            privSecret,
            secret,
            defaultSecurityLevel,
        )

    def createChannel(self, domain, address, localAddress, mtu):
        try:
            transportClass = self.TRANSPORTS[domain]
        except KeyError as err:
            errmsg = f"Unsupported transport domain: {transportClass.DOMAIN}"
            raise ValueError(errmsg) from err

        address = transportClass.normalizeAddress(
            address,
            AddressUsage.LISTENER,
        )

        localAddress = transportClass.normalizeAddress(localAddress)

        try:
            transports = self.transports[domain]
        except KeyError:
            transports = {}
            self.transports[domain] = transports

        try:
            transport = transports[localAddress]
        except KeyError:
            if mtu is None:
                transport = transportClass(*localAddress)
            else:
                transport = transportClass(*localAddress, mtu=mtu)

            self.multiplexor.register(transport, self.pipeline)
            transports[localAddress] = transport

        return TransportChannel(transport, address)

    def v1Manager(self, channel, autowait, community = None):
        if community is None:
            community = self.defaultCommunity

        return SNMPv1Manager(
            self.v1_admin,
            channel,
            community,
            autowait,
        )

    def v2cManager(self, channel, autowait, community = None):
        if community is None:
            community = self.defaultCommunity

        return SNMPv2cManager(
            self.v2c_admin,
            channel,
            community,
            autowait,
        )

    def v3Manager(self,
        channel,
        autowait,
        engineID = None,
        defaultSecurityLevel = None,
        defaultUser = None,
        namespace = "",
    ):
        if defaultUser is None:
            defaultUserName = self.usm.defaultUserName(namespace)

            if defaultUserName is None:
                errmsg = "An SNMPv3 Manager requires a default username." \
                    " Before calling Manager(), you should first configure" \
                    " the users "

                if namespace:
                    errmsg += f"in namespace \"{namespace}\""
                else:
                    errmsg += "for this engine"

                errmsg += " by calling addUser(). If you prefer to" \
                    " communicate unsecurely, you may instead pass a" \
                    " username to Manager() via the \"defaultUser\" keyword" \
                    " argument."

                raise TypeError(errmsg)
        else:
            defaultUserName = defaultUser.encode()

        if defaultSecurityLevel is None:
            defaultSecurityLevel = self.usm.defaultSecurityLevel(
                defaultUserName,
                namespace,
            )

            if defaultSecurityLevel is None:
                if defaultUser is None:
                    errmsg = "Successfully inferred the default username"

                    if namespace:
                        errmsg += f" for namespace \"{namespace}\""

                    errmsg += ", but not the default security level"
                    raise SNMPLibraryBug(errmsg)
                else:
                    defaultSecurityLevel = noAuthNoPriv
        else:
            maxSecurityLevel = self.usm.maxSecurityLevel(
                defaultUserName,
                namespace,
            )

            if defaultSecurityLevel > maxSecurityLevel:
                errmsg = "The security configuration for user" \
                    f" \"{defaultUserName.decode()}\""

                if namespace:
                    errmsg += f" in namespace \"{namespace}\""

                errmsg += " does not include a"

                if not maxSecurityLevel.auth:
                    errmsg += "n authentication protocol"
                elif defaultSecurityLevel.priv:
                    errmsg += " privacy protocol"

                errmsg += f"; please call the addUser() method to update" \
                    " the configuration."

                raise ValueError(errmsg)


        return SNMPv3Manager(
            self.scheduler,
            self.v3_table,
            self.v3_sorter,
            channel,
            namespace,
            defaultUserName,
            defaultSecurityLevel,
            engineID=engineID,
            autowait=autowait,
        )

    def Manager(self,
        address,
        version = None,
        domain = None,
        localAddress = None,
        mtu = None,
        autowait = None,
        **kwargs,
    ):
        if version is None:
            version = self.defaultVersion
        elif not isinstance(version, ProtocolVersion):
            version = ProtocolVersion(version)

        if domain is None:
            domain = self.defaultDomain

        channel = self.createChannel(domain, address, localAddress, mtu)

        if autowait is None:
            autowait = self.autowaitDefault

        if version == ProtocolVersion.SNMPv3:
            return self.v3Manager(channel, autowait, **kwargs)
        elif version == ProtocolVersion.SNMPv2c:
            return self.v2cManager(channel, autowait, **kwargs)
        elif version == ProtocolVersion.SNMPv1:
            return self.v1Manager(channel, autowait, **kwargs)
        else:
            raise ValueError(f"Unsupported protocol version: {str(version)}")

class Engine(GenericEngine):
    def __init__(self, *args, **kwargs):
        multiplexor = UdpMultiplexor()
        scheduler = Scheduler(multiplexor.poll)
        super().__init__(multiplexor, scheduler, *args, **kwargs)

    def poll(self, *handles):
        poller = RequestPoller(self.scheduler)

        for handle in handles:
            poller.register(handle)

        return poller
