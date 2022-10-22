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

class UserBasedSecurityAdministration:
    def __init__(self):
        self.lock = threading.Lock()
        self.engines    = {}
        self.namespaces = {}

        self.securityModule = UserBasedSecurityModule()

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

    def addUser(self, userName, authProtocol=None, authSecret=None,
            privProtocol=None, privSecret=None, secret=b"",
            default=False, defaultSecurityLevel=None, namespace=""):
        credentials = dict()
        if authProtocol is None:
            maxSecurityLevel = noAuthNoPriv
        else:
            if privProtocol is None:
                maxSecurityLevel = authNoPriv
            else:
                maxSecurityLevel = authPriv
                credentials["privProtocol"] = privProtocol
                credentials["privSecret"] = privSecret or secret

            credentials["authProtocol"] = authProtocol
            credentials["authSecret"] = authSecret or secret

        if defaultSecurityLevel is None:
            defaultSecurityLevel = maxSecurityLevel
        elif defaultSecurityLevel > maxSecurityLevel:
            errmsg = "{} is required in order to support {}"
            param = "privProtocol" if maxSecurityLevel.auth else "authProtocol"
            raise ValueError(errmsg.format(param, defaultSecurityLevel))

        with self.lock:
            try:
                space = self.namespaces[namespace]
            except KeyError:
                space = NameSpace(userName)
                self.namespaces[namespace] = space
            else:
                if userName in space:
                    errmsg = f"User \"{userName}\" is already defined"

                    if namespace:
                        errmsg += f" in namespace \"{namespace}\""

                    raise ValueError(errmsg)

                if default:
                    space.defaultUserName = userName

            space.addUser(userName, defaultSecurityLevel, credentials)

    def getDefaultSecurityLevel(self, userName, namespace=""):
        space = self.getNameSpace(namespace)

        try:
            user = space.getUser(userName)
        except KeyError as err:
            errmsg = f"No user \"{userName}\""

            if namespace:
                errmsg += f" in namespace \"{namespace}\""

            raise ValueError(errmsg) from err

        return user.defaultSecurityLevel

    def getDefaultUser(self, namespace=""):
        return self.getNameSpace(namespace).defaultUserName

    def getNameSpace(self, namespace=""):
        try:
            return self.namespaces[namespace]
        except KeyError as err:
            errmsg = "No users defined"

            if namespace:
                errmsg += f" in namespace \"{namespace}\""

            raise ValueError(errmsg) from err

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
                    self.securityModule.addUser(
                        engineID,
                        userName.encode(),
                        auth,
                        priv,
                    )

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

class Engine:
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
        # Read-only variables
        self.defaultVersion         = defaultVersion
        self.defaultDomain          = defaultDomain
        self.defaultSecurityModel   = defaultSecurityModel
        self.autowaitDefault        = autowait

        self.dispatcher = Dispatcher()
        self.lock = threading.Lock()

        self.transports = set()
        self.mpv1 = None
        self.mpv2c = None
        self.mpv3 = None

        self._usm = None

    @property
    def usm(self):
        if self._usm is None:
            self._usm = UserBasedSecurityAdministration()
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
            raise ValueError(self.UNSUPPORTED.format(transport.DOMAIN))

        self.dispatcher.connectTransport(transport)
        self.transports.add(transport.DOMAIN)

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

        return SNMPv1Manager(self.dispatcher, locator, community, autowait)

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

        return SNMPv2cManager(self.dispatcher, locator, community, autowait)

    def v3Manager(self, locator, securityModel=None, engineID=None,
            defaultUserName=None, defaultSecurityLevel=None,
            namespace="", autowait=None):
        if securityModel is None:
            securityModel = self.defaultSecurityModel
        elif not isinstance(securityModel, SecurityModel):
            securityModel = SecurityModel(securityModel)

        if securityModel != SecurityModel.USM:
            raise ValueError(self.UNSUPPORTED.format(str(securityModel)))

        if defaultUserName is None:
            defaultUserName = self.usm.getDefaultUser(namespace)

        if defaultSecurityLevel is None:
            defaultSecurityLevel = self.usm.getDefaultSecurityLevel(
                defaultUserName,
                namespace,
            )

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
                self.mpv3.secure(self.usm.securityModule)

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

    def Manager(self, address, domain=None, version=None, **kwargs):
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
