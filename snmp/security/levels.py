__all__ = ["noAuthNoPriv", "authNoPriv", "authPriv"]

from . import SecurityLevel

noAuthNoPriv = SecurityLevel()
authNoPriv = SecurityLevel(auth=True)
authPriv = SecurityLevel(auth=True, priv=True)
