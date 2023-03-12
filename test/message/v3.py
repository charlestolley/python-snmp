__all__ = [
    "HeaderDataTest", "MessageFlagsTest",
    "ScopedPDUTest", "SNMPv3MessageTest",
]

import re
import unittest

from snmp.ber import *
from snmp.message.v3 import *
from snmp.message.v3 import pduTypes
from snmp.pdu import *
from snmp.security import *
from snmp.security.levels import *
from snmp.types import *

class MessageFlagsTest(unittest.TestCase):
    def testDefaultConstructor(self):
        flags = MessageFlags()
        self.assertFalse(flags.authFlag)
        self.assertFalse(flags.privFlag)
        self.assertFalse(flags.reportableFlag)

    def testNoAuthNoPriv(self):
        flags = MessageFlags(noAuthNoPriv)
        self.assertFalse(flags.authFlag)
        self.assertFalse(flags.privFlag)
        self.assertFalse(flags.reportableFlag)

    def testAuthNoPriv(self):
        flags = MessageFlags(authNoPriv)
        self.assertTrue(flags.authFlag)
        self.assertFalse(flags.privFlag)
        self.assertFalse(flags.reportableFlag)

    def testAuthPriv(self):
        flags = MessageFlags(authPriv)
        self.assertTrue(flags.authFlag)
        self.assertTrue(flags.privFlag)
        self.assertFalse(flags.reportableFlag)

    def testReportableFlagInit(self):
        flags = MessageFlags(reportable=True)
        self.assertFalse(flags.authFlag)
        self.assertFalse(flags.privFlag)
        self.assertTrue(flags.reportableFlag)

    def testRepr(self):
        flags = MessageFlags(authPriv, True)
        self.assertEqual(eval(repr(flags)), flags)

    def testDecodeEmpty(self):
        self.assertRaises(ParseError, MessageFlags.decode, b"\x04\x00")

    def testDecode(self):
        flags = MessageFlags.decode(b"\x04\x01\x07")
        self.assertTrue(flags.authFlag)
        self.assertTrue(flags.privFlag)
        self.assertTrue(flags.reportableFlag)

    def testDecodeLong(self):
        flags = MessageFlags.decode(b"\x04\x02\x07\x00")
        self.assertTrue(flags.authFlag)
        self.assertTrue(flags.privFlag)
        self.assertTrue(flags.reportableFlag)

    def testDecodeUnknownFlag(self):
        flags = MessageFlags.decode(b"\x04\x01\x09")
        self.assertTrue(flags.authFlag)
        self.assertFalse(flags.privFlag)
        self.assertFalse(flags.reportableFlag)

    def testSetAuth(self):
        flags = MessageFlags()
        flags.authFlag = True
        self.assertTrue(flags.authFlag)

    def testUnsetAuth(self):
        flags = MessageFlags(authNoPriv)
        flags.authFlag = False
        self.assertFalse(flags.authFlag)

    def testSetPrivInvalid(self):
        def assignPrivFlag(flags, priv):
            flags.privFlag = priv

        flags = MessageFlags()
        self.assertRaises(ValueError, assignPrivFlag, flags, True)

    def testSetPriv(self):
        flags = MessageFlags(authNoPriv)
        flags.privFlag = True
        self.assertTrue(flags.privFlag)

    def testUnsetAuth(self):
        flags = MessageFlags(authPriv)
        flags.privFlag = False
        self.assertFalse(flags.privFlag)

    def testSetReportableFlag(self):
        flags = MessageFlags()
        flags.reportableFlag = True
        self.assertTrue(flags.reportableFlag)

    def testUnSetReportableFlag(self):
        flags = MessageFlags(reportable=True)
        flags.reportableFlag = False
        self.assertFalse(flags.reportableFlag)

class HeaderDataTest(unittest.TestCase):
    def setUp(self):
        self.encoding = bytes.fromhex(re.sub(r"\n", "", """
            30 10
               02 04 17 39 27 45
               02 02 05 dc
               04 01 07
               02 01 03
        """))

        self.header = HeaderData(
            0x17392745,
            1500,
            MessageFlags(authPriv, True),
            SecurityModel.USM,
        )

    def testDecode(self):
        self.assertEqual(HeaderData.decode(self.encoding), self.header)

    def testEncode(self):
        self.assertEqual(self.header.encode(), self.encoding)

    def testRepr(self):
        self.assertEqual(eval(repr(self.header)), self.header)

class ScopedPDUTest(unittest.TestCase):
    def setUp(self):
        self.encoding = bytes.fromhex(re.sub(r"\n", "", """
            30 57
               04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
               04 0b 73 6f 6d 65 43 6f 6e 74 65 78 74
               a2 3a
                  02 04 f9 6b fa c3
                  02 01 00
                  02 01 00
                  30 2c
                     30 2a
                        06 07 2b 06 01 02 01 01 00
                        04 1f 54 68 69 73 20 73 74 72 69 6e 67 20 64 65 73
                           63 72 69 62 65 73 20 6d 79 20 73 79 73 74 65 6d
        """))

        self.scopedPDU = ScopedPDU(
            ResponsePDU(
                requestID=-110363965,
                variableBindings=VarBindList(
                    VarBind(
                        "1.3.6.1.2.1.1.0",
                        OctetString(b"This string describes my system"),
                    )
                )
            ),
            b"someEngineID",
            b"someContext",
        )

    def testDecode(self):
        scopedPDU = ScopedPDU.decode(self.encoding, types=pduTypes)
        self.assertEqual(scopedPDU, self.scopedPDU)

    def testEncode(self):
        self.assertEqual(self.scopedPDU.encode(), self.encoding)

    def testRepr(self):
        self.assertEqual(eval(repr(self.scopedPDU)), self.scopedPDU)

class SNMPv3MessageTest(unittest.TestCase):
    def setUp(self):
        self.plain = bytes.fromhex(re.sub(r"\n", "", """
            30 81 96
               02 01 03
               30 10
                  02 04 35 b8 30 e4
                  02 02 05 dc
                  04 01 00
                  02 01 03
               04 26
                  30 24
                     04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
                     02 01 66
                     02 03 11 d7 6d
                     04 08 73 6f 6d 65 55 73 65 72
                     04 00
                     04 00
               30 57
                  04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
                  04 0b 73 6f 6d 65 43 6f 6e 74 65 78 74
                  a2 3a
                     02 04 f9 6b fa c3
                     02 01 00
                     02 01 00
                     30 2c
                        30 2a
                           06 07 2b 06 01 02 01 01 00
                           04 1f 54 68 69 73 20 73 74 72 69 6e 67 20 64 65 73
                              63 72 69 62 65 73 20 6d 79 20 73 79 73 74 65 6d
        """))

        self.encrypted = bytes.fromhex(re.sub("\n", "", """
            30 55
               02 01 03
               30 10
                  02 04 6f 10 97 b5
                  02 02 05 dc
                  04 01 03
                  02 01 03
               04 26
                  30 24
                     04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
                     02 01 66
                     02 03 11 d7 6d
                     04 08 73 6f 6d 65 55 73 65 72
                     04 00
                     04 00
               04 16 54 68 69 73 20 64 61 74 61 20 69
                     73 20 65 6e 63 72 79 70 74 65 64
        """))

        self.plainMessage = SNMPv3Message(
            HeaderData(
                0x35b830e4,
                1500,
                MessageFlags(),
                SecurityModel.USM,
            ),
            ScopedPDU(
                ResponsePDU(
                    requestID=-110363965,
                    variableBindings=VarBindList(
                        VarBind(
                            "1.3.6.1.2.1.1.0",
                            OctetString(b"This string describes my system"),
                        )
                    )
                ),
                b"someEngineID",
                b"someContext",
            ),
            securityParameters = OctetString(
                bytes.fromhex(re.sub(r"\n", "", """
                    30 24
                       04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
                       02 01 66
                       02 03 11 d7 6d
                       04 08 73 6f 6d 65 55 73 65 72
                       04 00
                       04 00
                """))
            ),
        )

        self.encryptedMessage = SNMPv3Message(
            HeaderData(
                0x6f1097b5,
                1500,
                MessageFlags(authPriv),
                SecurityModel.USM,
            ),
            encryptedPDU = OctetString(b"This data is encrypted"),
            securityParameters = OctetString(
                bytes.fromhex(re.sub(r"\n", "", """
                    30 24
                       04 0c 73 6f 6d 65 45 6e 67 69 6e 65 49 44
                       02 01 66
                       02 03 11 d7 6d
                       04 08 73 6f 6d 65 55 73 65 72
                       04 00
                       04 00
                """))
            ),
        )

    def testDecodePlain(self):
        self.assertEqual(SNMPv3Message.decode(self.plain), self.plainMessage)

    def testDecodeEncrypted(self):
        self.assertEqual(
            SNMPv3Message.decode(self.encrypted),
            self.encryptedMessage,
        )

    def testEncodePlain(self):
        self.assertEqual(self.plainMessage.encode(), self.plain)

    def testEncodeEncrypted(self):
        self.assertEqual(self.encryptedMessage.encode(), self.encrypted)

    def testPlainRepr(self):
        self.assertEqual(eval(repr(self.plainMessage)), self.plainMessage)

    def testEncryptedRepr(self):
        self.assertEqual(
            eval(repr(self.encryptedMessage)),
            self.encryptedMessage,
        )

    def testSecurityParameters(self):
        self.assertIsNone(self.plainMessage.securityEngineID)
        self.assertIsNone(self.plainMessage.securityName)
        self.assertIsNone(self.encryptedMessage.securityEngineID)
        self.assertIsNone(self.encryptedMessage.securityName)

if __name__ == "__main__":
    unittest.main()
