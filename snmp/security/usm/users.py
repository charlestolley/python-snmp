__all__ = ["UserRegistry", "UserNameCollision"]

from snmp.exception import *
from snmp.security import *

from ..levels import *
from .credentials import *

class UserNameCollision(ValueError):
    pass

class UserConfig:
    def __init__(self, credentials, defaultSecurityLevel):
        self.credentials = credentials
        self.defaultSecurityLevel = defaultSecurityLevel

class NamespaceConfig:
    def __init__(self):
        self.defaultUserName = None
        self.users = {}

    def __contains__(self, userName):
        return userName in self.users

    def __getitem__(self, userName):
        return self.users[userName]

    def addUser(self, userName, credentials, defaultSecurityLevel, default):
        if userName in self.users:
            raise UserNameCollision(userName)

        config = UserConfig(credentials, defaultSecurityLevel)
        self.users[userName] = config

        if default:
            self.defaultUserName = userName

class UserRegistry:
    def __init__(self):
        self.localizedCredentials = {}
        self.namespaceConfigs = {}

    def addUser(self,
        userName,
        namespace,
        default = None,
        authProtocol = None,
        privProtocol = None,
        authSecret = None,
        privSecret = None,
        secret = None,
        defaultSecurityLevel = None
    ):
        if not userName:
            raise ValueError(f"Empty userName")
        elif len(userName) > 32:
            raise ValueError(f"userName is too long: {userName!r}")

        newNamespace = namespace not in self.namespaceConfigs

        if default is None:
            default = newNamespace
        elif newNamespace and not default:
            msg = "default may not be False for the first user in a namespace"
            raise ValueError(msg)

        credentials = self.makeCredentials(
            authProtocol,
            privProtocol,
            authSecret,
            privSecret,
            secret,
        )

        if defaultSecurityLevel is None:
            defaultSecurityLevel = credentials.maxSecurityLevel
        elif defaultSecurityLevel > credentials.maxSecurityLevel:
            errmsg = f"Unable to support {defaultSecurityLevel}"
            if credentials.maxSecurityLevel.auth:
                errmsg += " without a privProtocol"
            else:
                errmsg += " without an authProtocol"

            raise ValueError(errmsg)

        if newNamespace:
            config = NamespaceConfig()
        else:
            config = self.namespaceConfigs[namespace]

        config.addUser(userName, credentials, defaultSecurityLevel, default)

        if newNamespace:
            self.namespaceConfigs[namespace] = config

    def namespaces(self, userName):
        for name, config in self.namespaceConfigs.items():
            if userName in config:
                yield name

    def exists(self, userName, namespace):
        try:
            config = self.namespaceConfigs[namespace]
        except KeyError:
            return False

        return userName in config

    def credentials(self, userName, namespace, engineID):
        try:
            return self.localizedCredentials[namespace][userName][engineID]
        except KeyError:
            pass

        try:
            creds = self.namespaceConfigs[namespace][userName].credentials
        except KeyError as err:
            raise ValueError(
                f"User {userName!r} is not defined"
                f" in namespace \"{namespace}\""
            ) from err

        try:
            users = self.localizedCredentials[namespace]
        except KeyError:
            users = {}
            self.localizedCredentials[namespace] = users

        try:
            engines = users[userName]
        except KeyError:
            engines = {}
            users[userName] = engines

        localizedCredentials = creds.localize(engineID)
        engines[engineID] = localizedCredentials
        return localizedCredentials

    def defaultSecurityLevel(self, userName, namespace):
        return self.namespaceConfigs[namespace][userName].defaultSecurityLevel

    def defaultUserName(self, namespace):
        return self.namespaceConfigs[namespace].defaultUserName

    @staticmethod
    def makeCredentials(
        authProtocol,
        privProtocol,
        authSecret,
        privSecret,
        secret,
    ):
        if authProtocol is None:
            if (privProtocol is not None
            or authSecret is not None
            or secret is not None):
                raise TypeError("missing required argument: 'authProtocol'")
        elif authSecret is None and secret is None:
            raise TypeError("missing required argument: 'authSecret'")
        elif authSecret is not None and secret is not None:
            raise TypeError("'authSecret' and 'secret' are mutually exclusive")

        if privProtocol is None and privSecret is not None:
            raise TypeError("missing required argument: 'privProtocol'")

        if authProtocol is None:
            credentials = Credentials()
        elif privProtocol is None:
            credentials = AuthCredentials(authProtocol, authSecret or secret)
        else:
            credentials = AuthPrivCredentials(
                authProtocol,
                privProtocol,
                authSecret,
                privSecret,
                secret,
            )

        return credentials
