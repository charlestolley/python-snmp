__all__ = ["UserRegistry", "UserNameCollision"]

from snmp.exception import *
from snmp.security import *
from snmp.typing import *

from ..levels import *
from . import AuthProtocol, PrivProtocol
from .credentials import *

class UserNameCollision(ValueError):
    pass

class UserConfig:
    def __init__(self,
        credentials: Credentials,
        defaultSecurityLevel: SecurityLevel,
    ) -> None:
        self.credentials = credentials
        self.defaultSecurityLevel = defaultSecurityLevel

class NamespaceConfig:
    def __init__(self) -> None:
        self.defaultUserName: Optional[bytes] = None
        self.users: Dict[bytes, UserConfig] = {}

    def __contains__(self, userName: bytes) -> bool:
        return userName in self.users

    def __getitem__(self, userName: bytes) -> UserConfig:
        return self.users[userName]

    def addUser(self,
        userName: bytes,
        credentials: Credentials,
        defaultSecurityLevel: SecurityLevel,
        default: bool,
    ) -> None:
        if userName in self.users:
            raise UserNameCollision(userName)

        config = UserConfig(credentials, defaultSecurityLevel)
        self.users[userName] = config

        if default:
            self.defaultUserName = userName

class UserRegistry:
    def __init__(self) -> None:
        self.localizedCredentials = {}
        self.namespaceConfigs: Dict[str, NamespaceConfig] = {}

    def addUser(self,
        userName: bytes,
        namespace: str,
        default: Optional[bool] = None,
        authProtocol: Optional[Type[AuthProtocol]] = None,
        privProtocol: Optional[Type[PrivProtocol]] = None,
        authSecret: Optional[bytes] = None,
        privSecret: Optional[bytes] = None,
        secret: bytes = None,
        defaultSecurityLevel: Optional[SecurityLevel] = None,
    ) -> None:
        if not userName:
            raise ValueError(f"Empty userName")
        elif len(userName) > 32:
            raise ValueError(f"userName is too long: {userName}")

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

    def namespaces(self, userName: bytes) -> Iterable[str]:
        for name, config in self.namespaceConfigs.items():
            if userName in config:
                yield name

    def exists(self, userName: bytes, namespace: str):
        try:
            config = self.namespaceConfigs[namespace]
        except KeyError:
            return False

        return userName in config

    def credentials(self,
        userName: bytes,
        namespace: str,
        engineID: bytes,
    ) -> LocalizedCredentials:
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

    def defaultSecurityLevel(self,
        userName: bytes,
        namespace: str,
    ) -> SecurityLevel:
        return self.namespaceConfigs[namespace][userName].defaultSecurityLevel

    def defaultUserName(self, namespace) -> Optional[bytes]:
        try:
            return self.namespaceConfigs[namespace].defaultUserName
        except KeyError:
            return None

    @staticmethod
    def makeCredentials(
        authProtocol: Optional[Type[AuthProtocol]],
        privProtocol: Optional[Type[PrivProtocol]],
        authSecret: Optional[bytes],
        privSecret: Optional[bytes],
        secret:     Optional[bytes],
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
