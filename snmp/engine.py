import threading

from snmp.dispatcher import *
from snmp.manager.v1 import *
from snmp.manager.v2c import *
from snmp.manager.v3 import *
from snmp.message import *
import snmp.message.v1
import snmp.message.v2c
import snmp.message.v3
from snmp.security import *
from snmp.security.levels import *
from snmp.security.usm import *
from snmp.transport import *
from snmp.transport.udp import *

class DiscoveryGuard:
    def __init__(self):
        self.namespace = None
        self.refCount = 0

    def assign(self, namespace):
        assigned = True
        initialized = True

        if namespace != self.namespace:
            if self.refCount:
                assigned = False
            else:
                self.namespace = namespace
                initialized = False

        if assigned:
            self.refCount += 1

        return assigned, initialized

    def release(self, namespace):
        assert self.namespace == namespace
        assert self.refCount > 0

        self.refCount -= 1
        return self.refCount == 0

class UserEntry:
    def __init__(self, defaultSecurityLevel, credentials):
        self.credentials = credentials
        self.defaultSecurityLevel = defaultSecurityLevel

class NameSpace:
    def __init__(self, defaultUserName):
        self.defaultUserName = defaultUserName
        self.users = {}

    def __iter__(self):
        return self.users.items().__iter__()

    def __contains__(self, key):
        return self.users.__contains__(key)

    def addUser(self, userName, *args, **kwargs):
        self.users[userName] = UserEntry(*args, **kwargs)

    def getUser(self, userName):
        return self.users[userName]

class Engine:
    """An SNMP engine, as defined in :rfc:`3411#section-3.1.1`.

    The RFC definition specifies that "[t]here is a one-to-one association
    between an SNMP engine and the SNMP entity which contains it." An
    application using this library would be considered an SNMP entity, and
    so the creation of more than one :class:`Engine` in an application is
    not supported. The thread-safety of the :class:`Engine` class has not
    yet been evaluated, so an :class:`Engine` should not be shared across
    multiple threads.

    The use of a :const:`with` block to manage the :class:`Engine`'s
    lifetime is highly recommended, as it will automatically call
    :meth:`shutdown` upon completion. If not using a :const:`with` block,
    the user must manually call :meth:`shutdown` at the end of the
    :class:`Engine`'s life. Failure to do so may cause the application to
    hang, rather than terminating properly.
    """

    TRANSPORTS = {
        cls.DOMAIN: cls for cls in [
            UdpTransport,
        ]
    }

    UNSUPPORTED = "{} is not supported at this time"

    def __init__(self,
        defaultVersion=MessageProcessingModel.SNMPv3,
        defaultDomain=TransportDomain.UDP,
        defaultSecurityModel=SecurityModel.USM,
        autowait=True
    ):
        """
        :param snmp.message.MessageProcessingModel defaultVersion:
            Default value for the *version* parameter to the :meth:`Manager`
            factory method.
        :param snmp.transport.TransportDomain defaultDomain:
            Default Transport Domain for SNMP messages.

            .. note::

                At this time, UDP over IPv4 is the only supported transport
                domain.
        :param snmp.security.SecurityModel defaultSecurityModel:
            Default Security Model for SNMPv3 Managers.

            .. note::

                At this time, only the User-Based Security Model is supported
        :param bool autowait:
            Default value for the *autowait* parameter to the :meth:`Manager`
            factory method.
        """

        # Read-only variables
        self.defaultVersion         = defaultVersion
        self.defaultDomain          = defaultDomain
        self.defaultSecurityModel   = defaultSecurityModel
        self.autowaitDefault        = autowait

        self.dispatcher = Dispatcher()

        self.lock = threading.Lock()
        self.engines = {}
        self.namespaces = {}

        self.transports = set()
        self.mpv1 = None
        self.mpv2c = None
        self.mpv3 = None
        self.usm = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.shutdown()

    def shutdown(self):
        """Stop the background threads that listen for incoming messages"""

        self.dispatcher.shutdown()

    def registerRemoteEngine(self, engineID, namespace):
        with self.lock:
            try:
                guard = self.engines[engineID]
            except KeyError:
                guard = DiscoveryGuard()
                self.engines[engineID] = guard

            assigned, initialized = guard.assign(namespace)
            if assigned and not initialized:
                ns = self.namespaces[namespace]
                for userName, entry in ns:
                    auth, priv = self.localize(engineID, **entry.credentials)
                    self.usm.addUser(engineID, userName, auth, priv)

            return assigned

    def unregisterRemoteEngine(self, engineID, namespace):
        with self.lock:
            try:
                guard = self.engines[engineID]
            except KeyError:
                assert False, f"Engine {engineID} was never registered"
            else:
                if guard.release(namespace):
                    del self.engines[engineID]

    @staticmethod
    def localize(engineID, authProtocol=None, authSecret=None,
                           privProtocol=None, privSecret=None):
        auth = None
        priv = None

        if authProtocol is not None:
            auth = authProtocol(authProtocol.localize(authSecret, engineID))

            if privProtocol is not None:
                priv = privProtocol(authProtocol.localize(privSecret, engineID))

        return auth, priv

    # TODO: Provide a full docstring for this method
    def addUser(self, userName, authProtocol=None, authSecret=None,
            privProtocol=None, privSecret=None, secret=b"",
            default=False, defaultSecurityLevel=None, namespace=""):
        """Define a user under the User-Based Security Model"""

        kwargs = dict()
        if authProtocol is None:
            maxSecurityLevel = noAuthNoPriv
        else:
            if privProtocol is None:
                maxSecurityLevel = authNoPriv
            else:
                maxSecurityLevel = authPriv
                kwargs["privProtocol"] = privProtocol
                kwargs["privSecret"] = privSecret or secret

            kwargs["authProtocol"] = authProtocol
            kwargs["authSecret"] = authSecret or secret

        if defaultSecurityLevel is None:
            defaultSecurityLevel = maxSecurityLevel
        elif defaultSecurityLevel > maxSecurityLevel:
            errmsg = "{} is required in order to support {}"
            param = "privProtocol" if maxSecurityLevel.auth else "authProtocol"
            raise ValueError(errmsg.format(param, defaultSecurityLevel))

        userName = userName.encode()

        with self.lock:
            try:
                space = self.namespaces[namespace]
            except KeyError:
                space = NameSpace(userName)
                self.namespaces[namespace] = space
            else:
                if userName in space:
                    errmsg = "User \"{}\" is already defined"

                    if namespace:
                        errmsg += " in namespace \"{}\"".format(namespace)

                    raise ValueError(errmsg.format(userName.decode()))

            if default:
                space.defaultUserName = userName

            space.addUser(userName, defaultSecurityLevel, kwargs)

    def connectTransport(self, transport):
        if transport.DOMAIN in self.transports:
            errmsg = "{} is already handled by a different transport object"
            raise ValueError(errmsg.format(transport.DOMAIN))
        elif transport.DOMAIN not in self.TRANSPORTS:
            raise ValueError(self.UNSUPPORTED.format(transport.DOMAIN))

        self.dispatcher.connectTransport(transport)
        self.transports.add(transport.DOMAIN)

    def sendPdu(self, *args, **kwargs):
        return self.dispatcher.sendPdu(*args, **kwargs)

    def v1Manager(self, locator, community=b"", autowait=None):
        if autowait is None:
            autowait = self.autowaitDefault

        if locator.domain not in self.transports:
            transportClass = self.TRANSPORTS[locator.domain]
            self.dispatcher.connectTransport(transportClass())
            self.transports.add(locator.domain)

        if self.mpv1 is None:
            self.mpv1 = snmp.message.v1.MessageProcessor()
            self.dispatcher.addMessageProcessor(self.mpv1)

        return SNMPv1Manager(self, locator, community, autowait)

    def v2cManager(self, locator, community=b"", autowait=None):
        if autowait is None:
            autowait = self.autowaitDefault

        if locator.domain not in self.transports:
            transportClass = self.TRANSPORTS[locator.domain]
            self.dispatcher.connectTransport(transportClass())
            self.transports.add(locator.domain)

        if self.mpv2c is None:
            self.mpv2c = snmp.message.v2c.MessageProcessor()
            self.dispatcher.addMessageProcessor(self.mpv2c)

        return SNMPv2cManager(self, locator, community, autowait)

    # TODO: Add a defaultSecurityLevel parameter?
    def v3Manager(self, locator, securityModel=None, engineID=None,
            defaultUserName=None, namespace="", autowait=None):
        if securityModel is None:
            securityModel = self.defaultSecurityModel
        elif not isinstance(securityModel, SecurityModel):
            securityModel = SecurityModel(securityModel)

        if securityModel != SecurityModel.USM:
            raise ValueError(self.UNSUPPORTED.format(str(securityModel)))

        with self.lock:
            try:
                space = self.namespaces[namespace]
            except KeyError as err:
                errmsg = f"No users defined in namespace \"{namespace}\""
                raise ValueError(errmsg) from err

            if defaultUserName is None:
                defaultUserName = space.defaultUserName
            else:
                defaultUserName = defaultUserName.encode()

            try:
                defaultUser = space.getUser(defaultUserName)
            except KeyError as err:
                errmsg = "No such user in namespace \"{}\": \"{}\""
                raise ValueError(errmsg.format(namespace, defaultUserName)) from err
            else:
                defaultSecurityLevel = defaultUser.defaultSecurityLevel

        if autowait is None:
            autowait = self.autowaitDefault

        with self.lock:
            if locator.domain not in self.transports:
                transportClass = self.TRANSPORTS[locator.domain]
                self.dispatcher.connectTransport(transportClass())
                self.transports.add(locator.domain)

            if self.mpv3 is None:
                self.mpv3 = snmp.message.v3.MessageProcessor()
                self.dispatcher.addMessageProcessor(self.mpv3)

            if self.usm is None:
                self.usm = UserBasedSecurityModule()
                self.mpv3.secure(self.usm)

        return SNMPv3UsmManager(
            self,
            locator,
            namespace,
            defaultUserName,
            defaultSecurityLevel,
            engineID=engineID,
            autowait=autowait,
        )

    def Manager(self, address, domain=None, version=None, **kwargs):
        """Create an object to manage a remote engine

        Each object returned by this factory method acts as a proxy for a
        remote engine (aka an Agent), and provides methods representing each of
        the management operations defined for a particular version of SNMP.

        :param address:
            Address of the remote engine within the transport domain. For the
            UDP domain, the address may either be a :class:`str` containing an
            IPv4 address, or a tuple of (:class:`str`, :class:`int`), containnig
            the IPv4 address and UDP port.
        :param Optional[snmp.transport.TransportDomain] domain:
            Transport domain, (i.e. the medium for transmitting messages) that
            the Manager will use. If *domain* is :const:`None`, then the
            *defaultDomain* provided to the :class:`Engine` constructor will be
            used.

            .. note::

                At this time, UDP over IPv4 is the only supported transport
                domain.
        :param snmp.message.MessageProcessingModel version:
            The SNMP version that the Manager will conform to. If *version* is
            :const:`None`, then the *defaultVersion* parameter provided to the
            :class:`Engine` constructor will be used.
        :param Optional[bool] autowait:
            This keyword-only parameter sets the default for the *wait*
            parameter to the Manager's request methods. If omitted or
            :const:`None`, then the *autowait* parameter provided to the
            :class:`Engine` constructor will be used.

        Additional keyword-only parameters are available, based on the SNMP
        version of the Manager. The following parameters apply to the creation
        of an SNMPv3 Manager:

        :param Optional[snmp.security.SecurityModel] securityModel:
            SNMPv3 Security Model. If omitted or :const:`None`, the
            *defaultSecurityModel* parameter to the :class:`Engine` constructor
            will be used.

            .. note::

                At this time, only the User-Based Security Model is supported
        :param Optional[bytes] engineID:
            Engine ID of the remote engine. The Manager is fully capable of
            discovering engine IDs automatically, and so this parameter is very
            much optional. The general recommendation would be to always use
            authentication, in which case the only advantage of specifying an
            engine ID manually would be a slight reduction in network traffic,
            unless the specified engine ID is incorrect, in which case a slight
            *increase* in network traffic is possible. The other advantage
            worth noting only applies so long as the Manager does not receive
            an authenticated messages. A Manager will update its stored engine
            ID if it receives a valid response containing a different engine
            ID. However, and unauthenticated response cannot overwrite an
            authenticated engine ID. A manually specified engine ID is treated
            as authentic, and so this can prevent a very narrow type of denial-
            of-service attack against a Manager that does not use
            authentication.
        :param Optional[str] defaultUserName:
            User name of the default user for outgoing requests. If omitted or
            :const:`None`, the default user of the namespace to which the
            managed engine belongs will be used. See :meth:`addUser` for
            further discussion of namespaces and default users.
        :param str namespace:
            The namespace of the managed engine. See :meth:`addUser` for
            further discussion of namespaces.

        When creating an SNMPv1 or SNMPv2c Manager, only one version-specific
        keyword parameter is supported:

        :param bytes community:
            Name of the default community for outgoing requests. If omitted,
            then the empty string (:const:`b""`) will be used as the default.
        """

        if domain is None:
            domain = self.defaultDomain

        try:
            locator = self.TRANSPORTS[domain].Locator(address)
        except KeyError as err:
            raise ValueError(self.UNSUPPORTED.format(domain)) from err

        if version is None:
            version = self.defaultVersion
        elif not isinstance(version, MessageProcessingModel):
            version = MessageProcessingModel(version)

        if version == MessageProcessingModel.SNMPv3:
            return self.v3Manager(locator, **kwargs)
        elif version == MessageProcessingModel.SNMPv2c:
            return self.v2cManager(locator, **kwargs)
        elif version == MessageProcessingModel.SNMPv1:
            return self.v1Manager(locator, **kwargs)
        else:
            raise ValueError(self.UNSUPPORTED.format(str(version)))
