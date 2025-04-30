__all__ = [
    "InvalidUserName", "InvalidEngineID",
    "UserRegistry", "UserNameCollision",
]

from snmp.exception import *
from snmp.security import *
from snmp.typing import *

from ..levels import *
from . import AuthProtocol, PrivProtocol
from .credentials import *

class InvalidEngineID(ValueError):
    pass

class InvalidUserName(ValueError):
    pass

class UserNameCollision(ValueError):
    pass

class UserConfig:
    def __init__(self,
        credentials: Credentials,
        defaultSecurityLevel: Optional[SecurityLevel] = None,
    ) -> None:
        if defaultSecurityLevel is None:
            defaultSecurityLevel = credentials.maxSecurityLevel
        elif defaultSecurityLevel > credentials.maxSecurityLevel:
            errmsg = f"Unable to support {defaultSecurityLevel}"
            if credentials.maxSecurityLevel.auth:
                errmsg += " without a privProtocol"
            else:
                errmsg += " without an authProtocol"

            raise ValueError(errmsg)

        self.credentials = credentials
        self.defaultSecurityLevel = defaultSecurityLevel

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, UserConfig):
            return NotImplemented

        return (self.credentials == other.credentials
            and self.defaultSecurityLevel == other.defaultSecurityLevel
        )

class NamespaceConfig:
    def __init__(self) -> None:
        self.defaultUserName: Optional[bytes] = None
        self.users: Dict[bytes, UserConfig] = {}

    def __iter__(self) -> Iterator[Tuple[bytes, UserConfig]]:
        for pair in self.users.items():
            yield pair

    def addUser(self,
        userName: bytes,
        credentials: Credentials,
        defaultSecurityLevel: Optional[SecurityLevel] = None,
        default: bool = False,
    ) -> None:
        config = UserConfig(credentials, defaultSecurityLevel)

        if userName in self.users:
            if (config != self.users[userName]
            or (default and (userName != self.defaultUserName))):
                raise UserNameCollision(userName)

        self.users[userName] = config
        if default or self.defaultUserName is None:
            self.defaultUserName = userName

    def findUser(self, userName: bytes) -> UserConfig:
        try:
            return self.users[userName]
        except KeyError as err:
            raise InvalidUserName(userName) from err

class RemoteEngine:
    def __init__(self,
        engineID: bytes,
        namespace: str,
        config: Optional[NamespaceConfig] = None,
    ) -> None:
        self.count = 1
        self.namespace: str = namespace
        self.users: Dict[bytes, LocalizedCredentials] = {}

        for userName, userConfig in (config if config is not None else []):
            self.addUser(engineID, userName, userConfig.credentials)

    def addUser(self,
        engineID: bytes,
        userName: bytes,
        credentials: Credentials,
    ) -> None:
        self.users[userName] = credentials.localize(engineID)

    def getCredentials(self, userName: bytes) -> LocalizedCredentials:
        try:
            return self.users[userName]
        except KeyError as err:
            raise InvalidUserName(userName) from err

    def assign(self, namespace: str) -> bool:
        match = False
        if namespace == self.namespace:
            match = True
            self.count += 1

        return match

    def release(self, namespace: str) -> bool:
        if self.namespace == namespace:
            assert self.count > 0
            self.count -= 1

        return self.count == 0

class UserRegistry:
    def __init__(self) -> None:
        self.engines: Dict[bytes, RemoteEngine] = {}
        self.namespaces: Dict[str, NamespaceConfig] = {}
        self.users: Dict[bytes, Dict[bytes, LocalizedCredentials]] = {}

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

        newNamespace = namespace not in self.namespaces

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
            config = self.namespaces[namespace]

        config.addUser(userName, credentials, defaultSecurityLevel, default)

        if newNamespace:
            self.namespaces[namespace] = config

        for engineID, engine in self.engines.items():
            if engine.namespace == namespace:
                engine.addUser(engineID, userName, credentials)

    def assign(self, engineID: bytes, namespace: str) -> bool:
        assigned = True

        try:
            peer = self.engines[engineID]
        except KeyError:
            config = self.namespaces.get(namespace)
            peer = RemoteEngine(engineID, namespace, config)
            self.engines[engineID] = peer
        else:
            assigned = peer.assign(namespace)

        return assigned

    def release(self, engineID: bytes, namespace: str) -> bool:
        released = False

        try:
            peer = self.engines[engineID]
        except KeyError as err:
            if __debug__:
                errmsg = f"Engine {engineID!r} is not assigned to a namespace"
                raise SNMPLibraryBug(errmsg) from err
        else:
            if peer.release(namespace):
                del self.engines[engineID]
                released = True

        return released

    def getCredentials(self,
        engineID: bytes,
        userName: bytes,
    ) -> LocalizedCredentials:
        try:
            peer = self.engines[engineID]
        except KeyError as err:
            raise InvalidEngineID(f"Unrecognized engine ID: {engineID!r}")

        return peer.getCredentials(userName)

    def getDefaultSecurityLevel(self,
        userName: bytes,
        namespace: str = "",
    ) -> SecurityLevel:
        config = self.getNamespace(namespace)
        return config.findUser(userName).defaultSecurityLevel

    def getDefaultUser(self, namespace: str = "") -> Optional[bytes]:
        return self.getNamespace(namespace).defaultUserName

    def getNamespace(self, namespace: str = "") -> NamespaceConfig:
        try:
            return self.namespaces[namespace]
        except KeyError as err:
            errmsg = "No users defined"

            if namespace:
                errmsg += f" in namespace \"{namespace}\""

            raise ValueError(errmsg) from err

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
