from importlib import import_module

from snmp.security.usm import PrivProtocol
from snmp.security.usm.priv import AesCfb128

class BlumenthalPrivProtocol(PrivProtocol):
    @classmethod
    def localizeKey(cls, authProtocol, intermediateKey, engineID):
        key = authProtocol.localizeKey(intermediateKey, engineID)

        if len(key) < cls.KEYLEN:
            key += authProtocol.computeHash(key)

        return key

module_path = AesCfb128.__module__.split(".")
assert module_path[:4] == ["snmp", "security", "usm", "priv"]
assert module_path[5] == "aes"

package = module_path[4]
aes = import_module(".aes", f"{__name__}.{package}")

variables = {varname: getattr(aes, varname) for varname in aes.__all__}
globals().update(variables)
__all__ = list(variables)
