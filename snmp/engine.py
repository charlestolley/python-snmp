from snmp.exception import *
from snmp.message import *
from snmp.pdu import *
from snmp.pipeline import *
from snmp.scheduler import *
from snmp.security import *
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
from snmp.v3.requests import *

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
        defaultSecurityModel: SecurityModel = SecurityModel.USM,
        defaultCommunity: bytes = b"",
        msgMaxSize: int = 1472,
        autowait: bool = True,
    ):
        # Read-only variables
        self.defaultVersion         = defaultVersion
        self.defaultDomain          = defaultDomain
        self.defaultSecurityModel   = defaultSecurityModel
        self.defaultCommunity       = defaultCommunity
        self.autowaitDefault        = autowait

        self.msgMaxSize = msgMaxSize
        self.multiplexor = UdpMultiplexor(self.msgMaxSize)
        self.scheduler = Scheduler(self.multiplexor.poll)
        self.usm = UserBasedSecurityModule()

        self.v1_admin = SNMPv1RequestAdmin(self.scheduler)
        self.v2c_admin = SNMPv2cRequestAdmin(self.scheduler)

        self.v3_sorter = MessageSorter(SNMPv3Interpreter(self.usm))
        self.v3_router = SNMPv3MessageRouter()
        self.v3_sorter.register(ReportPDU, self.v3_router)
        self.v3_sorter.register(ResponsePDU, self.v3_router)

        self.decoder = VersionDecoder()
        self.pipeline = Catcher(self.decoder)
        self.decoder.register(ProtocolVersion.SNMPv1, self.v1_admin)
        self.decoder.register(ProtocolVersion.SNMPv2c, self.v2c_admin)
        self.decoder.register(ProtocolVersion.SNMPv3, self.v3_sorter)

        self.transports: Dict[
            TransportDomain,
            Dict[Address, Transport[Address]]
        ] = {}

    def __enter__(self) -> "Engine":
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

    def shutdown(self) -> None:
        pass

    def connectTransport(self, transport: Transport[Tuple[str, int]]) -> None:
        self.multiplexor.register(transport, self.pipeline)

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
        **kwargs: Any,
    ):
        defaultUserName = kwargs.get("defaultUserName")
        namespace = kwargs.get("namespace", "")

        if defaultUserName is None:
            defaultUserName = self.usm.getDefaultUser(namespace)

            if defaultUserName is None:
                errmsg = "You must add at least one user before" \
                    " you can create an SNMPv3 Manager"
                raise NoDefaultUser(errmsg)

        if defaultSecurityLevel is None:
            defaultSecurityLevel = self.usm.getDefaultSecurityLevel(
                defaultUserName,
                namespace,
            )

        return SNMPv3Manager(
            self.scheduler,
            self.v3_router,
            self.v3_sorter,
            channel,
            namespace,
            defaultUserName.encode(),
            defaultSecurityLevel,
            engineID=engineID,
            autowait=autowait,
        )

    def Manager(self,
        address: Any,
        version: Optional[ProtocolVersion] = None,
        domain: Optional[TransportDomain] = None,
        localAddress: Any = None,
        autowait: Optional[bool] = None,
        **kwargs: Any,
    ) -> Union[
        SNMPv1Manager,
        SNMPv2cManager,
        SNMPv3Manager,
    ]:
        if domain is None:
            domain = self.defaultDomain

        if autowait is None:
            autowait = self.autowaitDefault

        try:
            transportClass = self.TRANSPORTS[domain]
        except KeyError as err:
            errmsg = f"Unsupported transport domain: {transportClass.DOMAIN}"
            raise ValueError(errmsg) from err

        address = transportClass.normalizeAddress(
            address,
            AddressUsage.LISTENER,
        )

        localAddress = transportClass.normalizeAddress(
            localAddress,
            AddressUsage.SENDER,
        )

        try:
            transports = self.transports[domain]
        except KeyError:
            transports = {}
            self.transports[domain] = transports

        try:
            transport = transports[localAddress]
        except KeyError:
            transport = transportClass(*localAddress)
            self.multiplexor.register(transport, self.pipeline)
            transports[localAddress] = transport

        channel = TransportChannel(transport, address)

        if version is None:
            version = self.defaultVersion
        elif not isinstance(version, ProtocolVersion):
            version = ProtocolVersion(version)

        if version == ProtocolVersion.SNMPv3:
            return self.v3Manager(channel, autowait, **kwargs)
        elif version == ProtocolVersion.SNMPv2c:
            return self.v2cManager(channel, autowait, **kwargs)
        elif version == ProtocolVersion.SNMPv1:
            return self.v1Manager(channel, autowait, **kwargs)
        else:
            raise ValueError(f"Unsupported protocol version: {str(version)}")
