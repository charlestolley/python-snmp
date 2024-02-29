__all__ = ["SecurityLevel", "noAuthNoPriv", "authNoPriv", "authPriv"]

from snmp.typing import *
from snmp.utils import typename

class SecurityLevel:
    def __init__(self, auth: Any = False, priv: Any = False) -> None:
        a = bool(auth)
        p = bool(priv)

        if p and not a:
            raise ValueError("Privacy without authentication is not valid")

        self._auth = a
        self._priv = p

    def __repr__(self) -> str:
        return "{}(auth={}, priv={})".format(
            typename(self),
            self.auth,
            self.priv
        )

    def __str__(self) -> str:
        return "{}{}".format(
            "auth" if self.auth else "noAuth",
            "Priv" if self.priv else "NoPriv"
        )

    @property
    def auth(self) -> bool:
        return self._auth

    @property
    def priv(self) -> bool:
        return self._priv

    def __eq__(self, other: Any) -> bool:
        try:
            result = (self.auth == other.auth and self.priv == other.priv)
        except AttributeError:
            return NotImplemented
        else:
            return cast(bool, result)

    def __lt__(self, other: "SecurityLevel") -> bool:
        if self.auth:
            return other.priv and not self.priv
        else:
            return other.auth

    def __ge__(self, other: "SecurityLevel") -> bool:
        return not self < other

noAuthNoPriv = SecurityLevel()
authNoPriv = SecurityLevel(auth=True)
authPriv = SecurityLevel(auth=True, priv=True)
