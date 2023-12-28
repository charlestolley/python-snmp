__all__ = ["InvalidUserName", "NamespaceConfig", "UserNameCollision"]

from snmp.security import *
from snmp.typing import *

from .credentials import *

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
        self.defaultUserName: Optional[str] = None
        self.users: Dict[str, UserConfig] = {}

    def __iter__(self) -> Iterator[Tuple[str, UserConfig]]:
        for pair in self.users.items():
            yield pair

    def addUser(self,
        userName: str,
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

    def findUser(self, userName: str) -> UserConfig:
        try:
            return self.users[userName]
        except KeyError as err:
            raise InvalidUserName(userName) from err
