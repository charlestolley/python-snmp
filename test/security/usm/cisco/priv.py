import re
import unittest

from snmp.security.usm.auth import HmacMd5, HmacSha
from snmp.security.usm.cisco.priv.pycryptodome.aes import (
    CiscoAesCfb192 as CiscoAesCfb192PyCrypto,
    CiscoAesCfb256 as CiscoAesCfb256PyCrypto,
)

class Something(unittest.TestCase):
    def test_md5(self):
        engineID = b"\x00" * 11 + b"\x02"
        password = b"maplesyrup"

        authProtocol = HmacMd5
        privProtocol = CiscoAesCfb256PyCrypto

        key = privProtocol.localizeKey(
            authProtocol,
            authProtocol.computeKey(password),
            engineID,
        )

        expected = bytes.fromhex(re.sub(r"\n", "", """
            52 6f 5e ed 9f cc e2 6f 89 64 c2 93 07 87 d8 2b
            79 ef f4 4a 90 65 0e e0 a3 a4 0a bf ac 5a cc 12
        """))

        self.assertEqual(key[:32], expected)

    def test_sha(self):
        engineID = b"\x00" * 11 + b"\x02"
        password = b"maplesyrup"

        authProtocol = HmacSha
        privProtocol = CiscoAesCfb256PyCrypto

        key = privProtocol.localizeKey(
            authProtocol,
            authProtocol.computeKey(password),
            engineID,
        )

        expected = bytes.fromhex(re.sub(r"\n", "", """
            66 95 fe bc 92 88 e3 62 82 23 5f c7 15 1f 12 84 97 b3 8f 3f
            9b 8b 6d 78 93 6b a6 e7 d1 9d fd 9c d2 d5 06 55 47 74 3f b5
        """))

        self.assertEqual(key, expected)

if __name__ == "__main__":
    unittest.main()
