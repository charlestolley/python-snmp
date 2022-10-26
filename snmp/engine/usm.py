__all__ = ["UsmControlModule"]

import threading

from snmp.security.levels import *
from snmp.security.usm import *

class DiscoveredEngine:
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

    def __getitem__(self, key):
        return self.users.__getitem__(key)

    def __setitem__(self, key, item):
        return self.users.__setitem__(key, item)

class UsmControlModule:
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
            authKey = authProtocol.localize(authSecret, engineID)
            auth = authProtocol(authKey)

            if privProtocol is not None:
                privKey = authProtocol.localize(privSecret, engineID)
                priv = privProtocol(privKey)

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
            errmsg = "Unable to support {} without the \"{}\" argument"
            param = "privProtocol" if maxSecurityLevel.auth else "authProtocol"
            raise ValueError(errmsg.format(defaultSecurityLevel, param))

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

            space[userName] = UserEntry(defaultSecurityLevel, credentials)

    def getDefaultSecurityLevel(self, userName, namespace=""):
        space = self.getNameSpace(namespace)

        try:
            user = space[userName]
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
                engine = self.engines[engineID]
            except KeyError:
                engine = DiscoveredEngine()
                self.engines[engineID] = engine

            assigned, initialized = engine.assign(namespace)

            # Read as "assigned but not initialized"
            if not initialized and assigned:
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
                engine = self.engines[engineID]
            except KeyError:
                assert False, f"Engine {engineID} was never registered"
            else:
                if engine.release(namespace):
                    del self.engines[engineID]
