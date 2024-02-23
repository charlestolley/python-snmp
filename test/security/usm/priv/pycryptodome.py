__all__ = ["AesCfb128TestCrypto", "DesCbcTestCrypto"]

from . import *

try:
    from snmp.security.usm.priv.pycryptodome.aes import *
    from snmp.security.usm.priv.pycryptodome.des import *
except ImportError as err:
    __all__.clear()
else:
    AesCfb128TestCrypto = makeAesCfb128Test(AesCfb128)
    DesCbcTestCrypto = makeDesCbcTest(DesCbc)
