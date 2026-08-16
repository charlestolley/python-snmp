__all__ = ["EsoAesCfb192TestOpenSSL", "EsoAesCfb256TestOpenSSL"]

from . import *

try:
    from snmp.security.usm.eso.priv.openssl.aes import *
except ImportError as err:
    __all__.clear()
else:
    EsoAesCfb192TestOpenSSL = makeAesCfb192Test(EsoAesCfb192)
    EsoAesCfb256TestOpenSSL = makeAesCfb256Test(EsoAesCfb256)

if __name__ == "__main__":
    import unittest
    unittest.main()
