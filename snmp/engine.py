from snmp.exception import SNMPException
from snmp.message import ProtocolVersion
from snmp.pdu import ReportPDU, ResponsePDU
from snmp.pipeline import *
from snmp.scheduler import Scheduler
from snmp.security import SecurityLevel
from snmp.security.usm import *
from snmp.transport import *
from snmp.transport.udp import *
from snmp.typing import *
from snmp.v1.manager import *
from snmp.v1.requests import *
from snmp.v2c.manager import *
from snmp.v2c.requests import *
from snmp.v3.interpreter import *
from snmp.v3.manager import *

Address = Tuple[str, int]

class NoDefaultUser(SNMPException):
    pass

class Engine:
    TRANSPORTS = {
        cls.DOMAIN: cls for cls in [
            UdpIPv4Socket,
            UdpIPv6Socket,
        ]
    }

    def __init__(self,
        defaultVersion: ProtocolVersion = ProtocolVersion.SNMPv3,
        defaultDomain: TransportDomain = TransportDomain.UDP_IPv4,
        defaultCommunity: bytes = b"",
        verboseLogging: bool = False,
        autowait: bool = True,
    ):
        # Read-only variables
        self.defaultVersion         = defaultVersion
        self.defaultDomain          = defaultDomain
        self.defaultCommunity       = defaultCommunity
        self.autowaitDefault        = autowait

        self.multiplexor = UdpMultiplexor()
        self.scheduler = Scheduler(self.multiplexor.poll)

        self.v1_admin = SNMPv1RequestAdmin(self.scheduler)
        self.v2c_admin = SNMPv2cRequestAdmin(self.scheduler)

        self.usm = UserBasedSecurityModule()
        self.v3_sorter = SNMPv3MessageSorter(SNMPv3Interpreter(self.usm))
        self.v3_router = SNMPv3MessageRouter()
        self.v3_sorter.register(ReportPDU, self.v3_router)
        self.v3_sorter.register(ResponsePDU, self.v3_router)

        self.decoder = VersionDecoder()
        self.pipeline = Catcher(self.decoder, verbose=verboseLogging)
        self.decoder.register(ProtocolVersion.SNMPv1, self.v1_admin)
        self.decoder.register(ProtocolVersion.SNMPv2c, self.v2c_admin)
        self.decoder.register(ProtocolVersion.SNMPv3, self.v3_sorter)

        self.transports: Dict[
            TransportDomain,
            Dict[Address, Transport[Address]]
        ] = {}

    def addUser(self,
        user: str,
        namespace: str = "",
        default: Optional[bool] = None,
        authProtocol: Optional[Type[AuthProtocol]] = None,
        privProtocol: Optional[Type[PrivProtocol]] = None,
        authSecret: Optional[bytes] = None,
        privSecret: Optional[bytes] = None,
        secret: Optional[bytes] = None,
        defaultSecurityLevel: Optional[SecurityLevel] = None,
    ) -> None:
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

    def v1Manager(self,
        channel: TransportChannel[Address],
        autowait: bool,
        community: Optional[bytes] = None,
    ) -> SNMPv1Manager:
        if community is None:
            community = self.defaultCommunity

        return SNMPv1Manager(
            self.v1_admin,
            channel,
            community,
            autowait,
        )

    def v2cManager(self,
        channel: TransportChannel[Address],
        autowait: bool,
        community: Optional[bytes] = None,
    ) -> SNMPv2cManager:
        if community is None:
            community = self.defaultCommunity

        return SNMPv2cManager(
            self.v2c_admin,
            channel,
            community,
            autowait,
        )

    def v3Manager(self,
        channel: TransportChannel[Address],
        autowait: bool,
        engineID: Optional[bytes] = None,
        defaultSecurityLevel: Optional[SecurityLevel] = None,
        defaultUser: Optional[str] = None,
        namespace: str = "",
    ):
        if defaultUser is None:
            defaultUserName = self.usm.defaultUserName(namespace)

            if defaultUserName is None:
                errmsg = "An SNMPv3 Manager requires a default userName," \
                    " either via the 'defaultUserName' parameter, or by" \
                    " calling the addUser() method"

                if namespace:
                    errmsg += f" for namespace \"{namespace}\""

                errmsg += "."
                raise TypeError(errmsg)
        else:
            defaultUserName = defaultUser.encode()

        if defaultSecurityLevel is None:
            defaultSecurityLevel = self.usm.defaultSecurityLevel(
                defaultUserName,
                namespace,
            )

            if defaultSecurityLevel is None:
                errmsg = "Found default userName without default securityLevel"
                raise SNMPLibraryBug(errmsg)

        return SNMPv3Manager(
            self.scheduler,
            self.v3_router,
            self.v3_sorter,
            channel,
            namespace,
            defaultUserName,
            defaultSecurityLevel,
            engineID=engineID,
            autowait=autowait,
        )

    def Manager(self,
        address: Any,
        version: Optional[ProtocolVersion] = None,
        domain: Optional[TransportDomain] = None,
        localAddress: Any = None,
        mtu: Optional[int] = None,
        autowait: Optional[bool] = None,
        **kwargs: Any,
    ) -> Union[
        SNMPv1Manager,
        SNMPv2cManager,
        SNMPv3Manager,
    ]:
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
