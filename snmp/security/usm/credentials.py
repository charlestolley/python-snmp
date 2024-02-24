__all__ = ["Credentials", "LocalizedCredentials"]

from . import AuthProtocol, PrivProtocol

from snmp.security.levels import *
from snmp.typing import *

class LocalizedCredentials:
    def __init__(self,
        auth: Optional[AuthProtocol],
        priv: Optional[PrivProtocol],
    ) -> None:
        self.auth = auth
        self.priv = priv

class Credentials:
    def __init__(self,
        authProtocol: Optional[Type[AuthProtocol]] = None,
        authSecret: Optional[bytes] = None,
        privProtocol: Optional[Type[PrivProtocol]] = None,
        privSecret: Optional[bytes] = None,
        secret: bytes = b"",
    ) -> None:
        self.authProtocol = None
        self.authKey = None
        self.privProtocol = None
        self.privKey = None

        if authProtocol is None:
            self.maxSecurityLevel = noAuthNoPriv
        else:
            if privProtocol is None:
                self.maxSecurityLevel = authNoPriv
            else:
                self.maxSecurityLevel = authPriv

                self.privProtocol = privProtocol
                self.privKey = authProtocol.computeKey(privSecret or secret)

            self.authProtocol = authProtocol
            self.authKey = authProtocol.computeKey(authSecret or secret)

    def localize(self, engineID: bytes) -> LocalizedCredentials:
        auth = None
        priv = None

        if self.authProtocol is not None:
            key = self.authProtocol.localizeKey(self.authKey, engineID)
            auth = self.authProtocol(key)

            if self.privProtocol is not None:
                key = self.authProtocol.localizeKey(self.privKey, engineID)
                priv = self.privProtocol(key)

        return LocalizedCredentials(auth, priv)
