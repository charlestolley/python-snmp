import threading

from snmp.dispatcher import *
from snmp.manager.v3 import *
from snmp.message import *
from snmp.message.v3 import *
from snmp.security import *
from snmp.security.levels import *
from snmp.security.usm import *
from snmp.transport import *
from snmp.transport.udp import *

class DiscoveryGuard:
    def __init__(self):
        self.namespace = None
        self.refCount = 0

    def claim(self, namespace):
        acquired = True
        initialized = True

        if namespace != self.namespace:
            if self.refCount:
                acquired = False
            else:
                self.namespace = namespace
                initialized = False

        if acquired:
            self.refCount += 1
            #print(f"claim  (\"{self.namespace}\"): refCount = {self.refCount}")

        return acquired, initialized

    def release(self, namespace):
        assert self.namespace == namespace
        assert self.refCount > 0
        self.refCount -= 1
        #print(f"release(\"{self.namespace}\"): refCount = {self.refCount}")
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
    TRANSPORTS = {
        cls.DOMAIN: cls for cls in [
            UdpTransport,
        ]
    }

    UNSUPPORTED = "{} is not supported at this time"

    def __init__(self, lockType=threading.Lock,
            defaultDomain=TransportDomain.UDP,
            defaultVersion=MessageProcessingModel.SNMPv3,
            defaultSecurityModel=SecurityModel.USM,
            autowait=True):

        self.defaultDomain = defaultDomain
        self.defaultVersion = defaultVersion
        self.defaultSecurityModel = defaultSecurityModel
        self.autowaitDefault = autowait
        self.dispatcher = Dispatcher(lockType=lockType)

        self.lock = lockType()
        self.lockType = lockType

        self.engines = {}
        self.namespaces = {}

        self.transports = set()
        self.mpv3 = None
        self.usm = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.shutdown()

    def shutdown(self):
        self.dispatcher.shutdown()

    def registerRemoteEngine(self, engineID, namespace):
        with self.lock:
            try:
                guard = self.engines[engineID]
            except KeyError:
                guard = DiscoveryGuard()
                self.engines[engineID] = guard

            acquired, initialized = guard.claim(namespace)
            if acquired and not initialized:
                space = self.namespaces[namespace]
                for userName, userEntry in space:
                    kwargs = self.localize(engineID, **userEntry.credentials)
                    self.usm.addUser(engineID, userName, **kwargs)

            return acquired

    def unregisterRemoteEngine(self, engineID, namespace):
        with self.lock:
            try:
                guard = self.engines[engineID]
            except KeyError:
                assert False, f"Engine {engineID} was never registered"
            else:
                if guard.release(namespace):
                    del self.engines[engineID]
                    #print(list(self.engines.keys()))

    @staticmethod
    def localize(engineID, authProtocol=None, authSecret=None,
                           privProtocol=None, privSecret=None):
        kwargs = dict()
        if authProtocol is not None:
            kwargs["authProtocol"] = authProtocol
            kwargs["authKey"] = authProtocol.localize(authSecret, engineID)

            if privProtocol is not None:
                kwargs["privProtocol"] = privProtocol
                kwargs["privKey"] = authProtocol.localize(privSecret, engineID)

        return kwargs

    def addUser(self, userName, authProtocol=None, authSecret=None,
            privProtocol=None, privSecret=None, secret=b"",
            default=False, defaultSecurityLevel=None, namespace=""):
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

    def v1Manager(self, locator):
        pass

    def v2cManager(self, locator, community=b"public"):
        pass

    def v3Manager(self, locator, securityModel=None, engineID=None,
            defaultUserName=None, namespace="", autowait=None):
        if securityModel is None:
            securityModel = self.defaultSecurityModel
        elif not isinstance(securityModel, SecurityModel):
            securityModel = SecurityModel(securityModel)

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

        if locator.domain not in self.transports:
            transportClass = self.TRANSPORTS[locator.domain]
            self.dispatcher.connectTransport(transportClass())
            self.transports.add(locator.domain)

        if self.mpv3 is None:
            self.mpv3 = MessageProcessor(lockType=self.lockType)
            self.dispatcher.addMessageProcessor(self.mpv3)

        if securityModel == SecurityModel.USM:
            if self.usm is None:
                self.usm = SecurityModule(lockType=self.lockType)
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
        else:
            raise ValueError(self.UNSUPPORTED.format(str(securityModel)))

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
        elif version == MessageProcessingModel.SNMPv2:
            return self.v2Manager(locator, **kwargs)
        elif version == MessageProcessingModel.SNMPv1:
            return self.v1Manager(locator, **kwargs)
        else:
            raise ValueError(self.UNSUPPORTED.format(str(version)))
