__all__ = ["CiscoAesCfb192TestPyCrypto", "CiscoAesCfb256TestPyCrypto"]

from . import makeAesCfb192Test, makeAesCfb256Test

try:
    from snmp.security.usm.cisco.priv.pycryptodome.aes import *
except ImportError as err:
    __all__.clear()
else:
    CiscoAesCfb192TestPyCrypto = makeAesCfb192Test(CiscoAesCfb192)
    CiscoAesCfb256TestPyCrypto = makeAesCfb256Test(CiscoAesCfb256)

if __name__ == "__main__":
    import unittest
    unittest.main()
