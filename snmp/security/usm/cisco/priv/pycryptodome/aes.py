__all__ = ["CiscoAesCfb192", "CiscoAesCfb256"]

from snmp.security.usm.cisco.priv import DoubleLocalizePrivProtocol
from snmp.security.usm.priv.pycryptodome.aes import AesCfb
from snmp.smi import OID

class CiscoAesCfb192(AesCfb, DoubleLocalizePrivProtocol):
    ALGORITHM = OID.parse("1.3.6.1.4.1.9.12.6.1.1")
    KEYLEN = 192 // 8

class CiscoAesCfb256(AesCfb, DoubleLocalizePrivProtocol):
    ALGORITHM = OID.parse("1.3.6.1.4.1.9.12.6.1.2")
    KEYLEN = 256 // 8
