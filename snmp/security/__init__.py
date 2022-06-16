__all__ = ["SecurityLevel", "SecurityModel", "SecurityParameters"]

import enum
from snmp.utils import typename

class SecurityLevel:
    def __init__(self, auth=False, priv=False):
        self._auth = False
        self._priv = False

        self.auth = auth
        self.priv = priv

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

    @auth.setter
    def auth(self, value):
        if not value and self.priv:
            msg = "Cannot disable authentication while privacy is enabled"
            raise ValueError(msg)

        self._auth = bool(value)

    @priv.setter
    def priv(self, value):
        if value and not self.auth:
            msg = "Cannot enable privacy while authentication is disabled"
            raise ValueError(msg)

        self._priv = bool(value)

    def __eq__(a, b):
        return a.auth == b.auth and a.priv == b.priv

    def __lt__(a, b):
        if a.auth:
            return b.priv and not a.priv
        else:
            return b.auth

    def __ge__(a, b):
        return not a < b

class SecurityModel(enum.IntEnum):
    USM = 3

class SecurityParameters:
    def __init__(self, engineID, userName):
        self.securityEngineID = engineID
        self.securityName = userName

    def __repr__(self):
        return f"{typename(self)}({self.securityEngineID}, {self.securityName})"
