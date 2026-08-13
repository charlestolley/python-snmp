from collections import deque

from snmp.exception import *
from snmp.message import ProtocolVersion
from snmp.pdu import ReportPDU, ResponsePDU, SNMPv2TrapPDU
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
from snmp.v2c.sorter import *
from snmp.v2c.traps import *
from snmp.v3.interpreter import *
from snmp.v3.manager import *
from snmp.v3.traps import *

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
        self.v1_filter = \
            ReceiveAddressFilter(self.v1_admin, verbose=verboseLogging)

        self.v2c_admin = SNMPv2cRequestAdmin(self.scheduler)
        self.v2c_trap_decoder = SNMPv2cTrapDecoder()
        self.v2c_response_filter = \
            ReceiveAddressFilter(self.v2c_admin, verbose=verboseLogging)
        self.v2c_trap_filter = \
            ReceiveAddressFilter(self.v2c_trap_decoder, verbose=verboseLogging)

        self.v2c_sorter = SNMPv2cMessageSorter()
        self.v2c_sorter.register(ResponsePDU, self.v2c_response_filter)
        self.v2c_sorter.register(SNMPv2TrapPDU, self.v2c_trap_filter)

        self.v3_table = SNMPv3MessageTable()
        self.v3_trap_decoder = SNMPv3TrapDecoder()
        self.v3_response_filter = \
            ReceiveAddressFilter(self.v3_table, verbose=verboseLogging)
        self.v3_trap_filter = \
            ReceiveAddressFilter(self.v3_trap_decoder, verbose=verboseLogging)

        self.usm = UserBasedSecurityModule()
        self.v3_sorter = SNMPv3MessageSorter(SNMPv3Interpreter(self.usm))
        self.v3_sorter.register(ReportPDU, self.v3_response_filter)
        self.v3_sorter.register(ResponsePDU, self.v3_response_filter)
        self.v3_sorter.register(SNMPv2TrapPDU, self.v3_trap_filter)

        self.decoder = VersionDecoder()
        self.pipeline = Catcher(self.decoder, verbose=verboseLogging)
        self.decoder.register(ProtocolVersion.SNMPv1, self.v1_filter)
        self.decoder.register(ProtocolVersion.SNMPv2c, self.v2c_sorter)
        self.decoder.register(ProtocolVersion.SNMPv3, self.v3_sorter)

        self.transports = {}

    def __del__(self):
        try:
            self.multiplexor.close()
        except AttributeError:
            # In case the constructor gets an invalid argument name
            pass

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

    def selectTransportClass(self, domain):
        if domain is None:
            domain = self.defaultDomain

        try:
            return self.TRANSPORTS[domain]
        except KeyError as err:
            errmsg = f"Unsupported transport domain: {domain}"
            raise ValueError(errmsg) from err

    def findOrCreateTransport(self, cls, address, mtu=None):
        try:
            return self.transports[cls.DOMAIN][address]
        except KeyError:
            pass

        if mtu is None:
            transport = cls(*address)
        else:
            transport = cls(*address, mtu=mtu)

        self.multiplexor.register(transport, self.pipeline)
        self.transports.setdefault(cls.DOMAIN, dict())[address] = transport
        return transport

    def v1Manager(self, channel, autowait, community = None):
        if community is None:
            community = self.defaultCommunity

        self.v1_filter.allow(channel.transport)

        return SNMPv1Manager(
            self.v1_admin,
            channel,
            community,
            autowait,
        )

    def v2cManager(self, channel, autowait, community = None):
        if community is None:
            community = self.defaultCommunity

        self.v2c_response_filter.allow(channel.transport)

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

        self.v3_response_filter.allow(channel.transport)

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

    def resolveVersion(self, version):
        if version is None:
            version = self.defaultVersion
        elif not isinstance(version, ProtocolVersion):
            version = ProtocolVersion(version)

        return version

    def Manager(self,
        address,
        version = None,
        domain = None,
        localAddress = None,
        mtu = None,
        autowait = None,
        **kwargs,
    ):
        version = self.resolveVersion(version)
        tc = self.selectTransportClass(domain)
        address = tc.normalizeAddress(address, AddressUsage.LISTENER)
        localAddress = tc.normalizeAddress(localAddress)
        transport = self.findOrCreateTransport(tc, localAddress, mtu=mtu)
        channel = TransportChannel(transport, address)

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

    def setTrapHandler(self,
        handler,
        version=None,
        domain=None,
        address=None,
        mtu=None,
    ):
        version = self.resolveVersion(version)
        if version == ProtocolVersion.SNMPv3:
            trap_decoder = self.v3_trap_decoder
            trap_filter = self.v3_trap_filter
        elif version == ProtocolVersion.SNMPv2c:
            trap_decoder = self.v2c_trap_decoder
            trap_filter = self.v2c_trap_filter
        elif version == ProtocolVersion.SNMPv1:
            raise ValueError(f"{typename(self)} does not support SNMPv1 traps")
        else:
            raise ValueError(f"Unsupported protocol version: {str(version)}")

        tc = self.selectTransportClass(domain)
        address = tc.normalizeAddress(address, AddressUsage.TRAP_LISTENER)
        transport = self.findOrCreateTransport(tc, address, mtu=mtu)
        trap_decoder.setHandler(handler)
        trap_filter.allow(transport)

    def TrapListener(self,
        version=None,
        domain=None,
        localAddress=None,
        mtu=None,
    ):
        listener = self.newTrapListener()
        self.setTrapHandler(listener, version, domain, localAddress, mtu)
        return listener

class TrapListener:
    def __init__(self, sleep_function):
        self.queue = deque()
        self.sleep = sleep_function

    def trap(self, vblist, **kwargs):
        self.queue.append((vblist, kwargs))

    def listen(self):
        while len(self.queue) == 0:
            self.sleep()

        return self.queue.popleft()

class Engine(GenericEngine):
    def __init__(self, *args, **kwargs):
        try:
            multiplexor = kwargs.pop("multiplexor")
        except KeyError:
            multiplexor = UdpMultiplexor()

        scheduler = Scheduler(multiplexor.poll)
        super().__init__(multiplexor, scheduler, *args, **kwargs)

    def newTrapListener(self):
        return TrapListener(self.idle)

    def idle(self):
        if self.scheduler:
            self.scheduler.wait()
        else:
            self.multiplexor.poll()

    def poll(self, *handles):
        poller = RequestPoller(self.scheduler)

        for handle in handles:
            poller.register(handle)

        return poller
