__all__ = ["AesCfb128TestOpenSSL", "DesCbcTestOpenSSL"]

from . import makeAesCfb128Test, makeDesCbcTest

try:
    from snmp.security.usm.priv.openssl.aes import *
    from snmp.security.usm.priv.openssl.des import *
except ImportError as err:
    __all__.clear()
else:
    AesCfb128TestOpenSSL = makeAesCfb128Test(AesCfb128)
    DesCbcTestOpenSSL = makeDesCbcTest(DesCbc)

if __name__ == "__main__":
    import unittest
    unittest.main()
