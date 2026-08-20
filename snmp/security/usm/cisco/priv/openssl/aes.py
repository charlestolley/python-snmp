__all__ = ["CiscoAesCfb192", "CiscoAesCfb256"]

from snmp.security.usm.cisco.priv import ReederPrivProtocol
from snmp.security.usm.priv.openssl import AES_192_CFB128, AES_256_CFB128
from snmp.security.usm.priv.openssl.aes import AesCfb
from snmp.smi import OID

class CiscoAesCfb192(AesCfb, ReederPrivProtocol):
    ALGORITHM = OID.parse("1.3.6.1.4.1.9.12.6.1.1")
    CIPHER = AES_192_CFB128
    KEYLEN = 192 // 8

class CiscoAesCfb256(AesCfb, ReederPrivProtocol):
    ALGORITHM = OID.parse("1.3.6.1.4.1.9.12.6.1.2")
    CIPHER = AES_256_CFB128
    KEYLEN = 256 // 8
