__all__ = ["EsoAesCfb192", "EsoAesCfb256"]

from snmp.security.usm.eso.priv import BlumenthalPrivProtocol
from snmp.security.usm.priv.openssl import AES_192_CFB128, AES_256_CFB128
from snmp.security.usm.priv.openssl.aes import AesCfb
from snmp.smi import OID

class EsoAesCfb192(AesCfb, BlumenthalPrivProtocol):
    ALGORITHM = OID.parse("1.3.6.1.4.1.14832.1.3")
    CIPHER = AES_192_CFB128
    KEYLEN = 192 // 8

class EsoAesCfb256(AesCfb, BlumenthalPrivProtocol):
    ALGORITHM = OID.parse("1.3.6.1.4.1.14832.1.4")
    CIPHER = AES_256_CFB128
    KEYLEN = 256 // 8
