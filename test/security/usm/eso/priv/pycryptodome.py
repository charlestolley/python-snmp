__all__ = ["EsoAesCfb192TestPyCrypto", "EsoAesCfb256TestPyCrypto"]

from . import *

try:
    from snmp.security.usm.eso.priv.pycryptodome.aes import *
except ImportError as err:
    __all__.clear()
else:
    EsoAesCfb192TestPyCrypto = makeAesCfb192Test(EsoAesCfb192)
    EsoAesCfb256TestPyCrypto = makeAesCfb256Test(EsoAesCfb256)

if __name__ == "__main__":
    import unittest
    unittest.main()
