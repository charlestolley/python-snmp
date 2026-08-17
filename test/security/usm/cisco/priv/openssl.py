__all__ = ["CiscoAesCfb192TestOpenSSL", "CiscoAesCfb256TestOpenSSL"]

from . import makeAesCfb192Test, makeAesCfb256Test

try:
    from snmp.security.usm.cisco.priv.openssl.aes import *
except ImportError as err:
    __all__.clear()
else:
    CiscoAesCfb192TestOpenSSL = makeAesCfb192Test(CiscoAesCfb192)
    CiscoAesCfb256TestOpenSSL = makeAesCfb256Test(CiscoAesCfb256)

if __name__ == "__main__":
    import unittest
    unittest.main()
