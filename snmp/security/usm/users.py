__all__ = [
    "InvalidUserName", "InvalidEngineID",
    "UserRegistry", "UserNameCollision",
]

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

class UserRegistry:
    def __init__(self) -> None:
        self.namespaces: Dict[str, NamespaceConfig] = {}
        self.users: Dict[bytes, Dict[bytes, LocalizedCredentials]] = {}

    def addUser(self,
        userName: bytes,
        authProtocol: Optional[Type[AuthProtocol]] = None,
        authSecret: Optional[bytes] = None,
        privProtocol: Optional[Type[PrivProtocol]] = None,
        privSecret: Optional[bytes] = None,
        secret: bytes = b"",
        default: bool = False,
        defaultSecurityLevel: Optional[SecurityLevel] = None,
        namespace: str = "",
    ) -> None:
        try:
            config = self.namespaces[namespace]
        except KeyError:
            config = NamespaceConfig()
            self.namespaces[namespace] = config

        credentials = Credentials(
            authProtocol,
            authSecret,
            privProtocol,
            privSecret,
            secret,
        )

        config.addUser(userName, credentials, defaultSecurityLevel, default)

    def assign(self, engineID: bytes, namespace: str) -> None:
        try:
            config = self.namespaces[namespace]
        except KeyError as err:
            config = NamespaceConfig()

        users = {}
        for userName, userConfig in config:
            user = userConfig.credentials.localize(engineID)
            users[userName] = user

        self.users[engineID] = users

    def getCredentials(self,
        engineID: bytes,
        userName: bytes,
    ) -> LocalizedCredentials:
        try:
            users = self.users[engineID]
        except KeyError as err:
            raise InvalidEngineID(f"Unrecognized engine ID: {engineID!r}")

        try:
            user = users[userName]
        except KeyError as err:
            errmsg = f"User \"{userName.decode()}\" is not defined" \
                f" for engine {engineID!r}"
            raise InvalidUserName(errmsg) from err

        return user

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
