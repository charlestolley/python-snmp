__all__ = ["SecurityLevel", "noAuthNoPriv", "authNoPriv", "authPriv"]

from snmp.utils import typename

class SecurityLevel:
    def __init__(self, auth = False, priv = False):
        a = bool(auth)
        p = bool(priv)

        if p and not a:
            raise ValueError("Privacy without authentication is not valid")

        self._auth = a
        self._priv = p

    def __repr__(self):
        return "{}(auth={}, priv={})".format(
            typename(self),
            self.auth,
            self.priv
        )

    def __str__(self):
        return "{}{}".format(
            "auth" if self.auth else "noAuth",
            "Priv" if self.priv else "NoPriv"
        )

    @property
    def auth(self):
        return self._auth

    @property
    def priv(self):
        return self._priv

    def __eq__(self, other):
        try:
            result = (self.auth == other.auth and self.priv == other.priv)
        except AttributeError:
            return NotImplemented
        else:
            return result

    def __lt__(self, other):
        if self.auth:
            return other.priv and not self.priv
        else:
            return other.auth

    def __ge__(self, other):
        return not self < other

noAuthNoPriv = SecurityLevel()
authNoPriv = SecurityLevel(auth=True)
authPriv = SecurityLevel(auth=True, priv=True)
