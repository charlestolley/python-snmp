__all__ = ["EsoAesCfb192", "EsoAesCfb256"]

from snmp.security.usm.eso.priv import BlumenthalPrivProtocol
from snmp.security.usm.priv.pycryptodome.aes import AesCfb
from snmp.smi import OID

class EsoAesCfb192(AesCfb, BlumenthalPrivProtocol):
    ALGORITHM = OID.parse("1.3.6.1.4.1.14832.1.3")
    KEYLEN = 192 // 8

class EsoAesCfb256(AesCfb, BlumenthalPrivProtocol):
    ALGORITHM = OID.parse("1.3.6.1.4.1.14832.1.4")
    KEYLEN = 256 // 8
