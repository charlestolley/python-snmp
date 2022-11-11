__all__ = [
    "SecurityLevel", "SecurityModel", "SecurityModule", "SecurityParameters",
]

from abc import abstractmethod
import enum

from snmp.typing import *
from snmp.utils import *

class SecurityLevel:
    def __init__(self, auth: Any = False, priv: Any = False) -> None:
        self._auth = False
        self._priv = False

        self.auth = auth
        self.priv = priv

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

    @auth.setter
    def auth(self, value: Any) -> None:
        _value = bool(value)
        if not _value and self.priv:
            msg = "Cannot disable authentication while privacy is enabled"
            raise ValueError(msg)

        self._auth = _value

    @property
    def priv(self) -> bool:
        return self._priv

    @priv.setter
    def priv(self, value: Any) -> None:
        _value = bool(value)
        if _value and not self.auth:
            msg = "Cannot enable privacy while authentication is disabled"
            raise ValueError(msg)

        self._priv = _value

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

class SecurityModel(enum.IntEnum):
    USM = 3

class SecurityParameters:
    def __init__(self, engineID: bytes, userName: bytes):
        self.securityEngineID = engineID
        self.securityName = userName

    def __repr__(self) -> str:
        return "{}({!r}, {!r})".format(
            typename(self),
            self.securityEngineID,
            self.securityName,
        )

class SecurityModule:
    @abstractmethod
    def processIncoming(self,
        msg: subbytes,
        securityLevel: SecurityLevel,
        timestamp: Optional[float] = None,
    ) -> Tuple[SecurityParameters, bytes]:
        ...

    @abstractmethod
    def prepareOutgoing(self,
        header: bytes,
        data: bytes,
        engineID: bytes,
        securityName: bytes,
        securityLevel: SecurityLevel,
    ) -> bytes:
        ...
