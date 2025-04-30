__all__ = [
    "AuthCredentials", "AuthPrivCredentials",
    "Credentials", "LocalizedCredentials",
]

from . import AuthProtocol, PrivProtocol

from snmp.security.levels import *
from snmp.typing import *

class LocalizedCredentials:
    def __init__(self,
        auth: Optional[AuthProtocol] = None,
        priv: Optional[PrivProtocol] = None,
    ) -> None:
        self.auth = auth
        self.priv = priv

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, LocalizedCredentials):
            return NotImplemented

        return self.auth == other.auth and self.priv == other.priv

class Credentials:
    def __init__(self):
        self.maxSecurityLevel = noAuthNoPriv

    def localize(self, engineID: bytes) -> LocalizedCredentials:
        return LocalizedCredentials()

class AuthCredentials(Credentials):
    def __init__(self,
        authProtocol: Type[AuthProtocol],
        authSecret: bytes,
    ):
        super().__init__()
        self.maxSecurityLevel = authNoPriv
        self.authProtocol = authProtocol
        self.authKey = self.authProtocol.computeKey(authSecret)

    def localizeAuth(self, engineID) -> AuthProtocol:
        key = self.authProtocol.localizeKey(self.authKey, engineID)
        return self.authProtocol(key)

    def localize(self, engineID) -> LocalizedCredentials:
        return LocalizedCredentials(self.localizeAuth(engineID))

class AuthPrivCredentials(AuthCredentials):
    def __init__(self,
        authProtocol: Type[AuthProtocol],
        privProtocol: Type[PrivProtocol],
        authSecret: Optional[bytes] = None,
        privSecret: Optional[bytes] = None,
        secret: Optional[bytes] = None,
    ):
        if secret is None:
            if authSecret is None:
                raise TypeError("missing required argument: 'authSecret'")
            elif privSecret is None:
                raise TypeError("missing required argument: 'privSecret'")

            super().__init__(authProtocol, authSecret)
            self.privKey = self.authProtocol.computeKey(privSecret)
        else:
            if authSecret is not None:
                errmsg = "'authSecret' and 'secret' are mutually exclusive"
                raise TypeError(errmsg)
            elif privSecret is not None:
                errmsg = "'privSecret' and 'secret' are mutually exclusive"
                raise TypeError(errmsg)

            super().__init__(authProtocol, secret)
            self.privKey = self.authKey

        self.maxSecurityLevel = authPriv
        self.privProtocol = privProtocol

    def localizePriv(self, engineID) -> PrivProtocol:
        key = self.authProtocol.localizeKey(self.privKey, engineID)
        return self.privProtocol(key)

    def localize(self, engineID: bytes) -> LocalizedCredentials:
        auth = self.localizeAuth(engineID)
        priv = self.localizePriv(engineID)
        return LocalizedCredentials(auth, priv)
