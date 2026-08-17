__all__ = ["AesCfb128TestCrypto", "DesCbcTestCrypto"]

from . import makeAesCfb128Test, makeDesCbcTest

try:
    from snmp.security.usm.priv.pycryptodome.aes import *
    from snmp.security.usm.priv.pycryptodome.des import *
except ImportError as err:
    __all__.clear()
else:
    AesCfb128TestCrypto = makeAesCfb128Test(AesCfb128)
    DesCbcTestCrypto = makeDesCbcTest(DesCbc)

if __name__ == "__main__":
    import unittest
    unittest.main()
