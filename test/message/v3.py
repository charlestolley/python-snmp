__all__ = ["MessageFlagsTest"]

import unittest

from snmp.ber import *
from snmp.message.v3 import *

class MessageFlagsTest(unittest.TestCase):
    def testAuthFlagInit(self):
        flags = MessageFlags(1)
        self.assertTrue(flags.authFlag)
        self.assertFalse(flags.privFlag)
        self.assertFalse(flags.reportableFlag)

    def testPrivFlagInit(self):
        flags = MessageFlags(3)
        self.assertTrue(flags.authFlag)
        self.assertTrue(flags.privFlag)
        self.assertFalse(flags.reportableFlag)

    def testReportableFlagInit(self):
        flags = MessageFlags(4)
        self.assertFalse(flags.authFlag)
        self.assertFalse(flags.privFlag)
        self.assertTrue(flags.reportableFlag)

    def testUnusedFlagInit(self):
        flags = MessageFlags(9)
        self.assertTrue(flags.authFlag)
        self.assertFalse(flags.privFlag)
        self.assertFalse(flags.reportableFlag)

    def testRepr(self):
        flags = MessageFlags(3)
        self.assertEqual(eval(repr(flags)), flags)

    def testDecodeEmpty(self):
        self.assertRaises(ParseError, MessageFlags.decode, b"\x04\x00")

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

    def testSetAuthFlag(self):
        flags = MessageFlags()
        self.assertFalse(flags.authFlag)
        flags.authFlag = True
        self.assertTrue(flags.authFlag)

    def testSetPrivFlag(self):
        flags = MessageFlags()
        self.assertFalse(flags.privFlag)
        flags.privFlag = True
        self.assertTrue(flags.privFlag)

    def testSetReportableFlag(self):
        flags = MessageFlags()
        self.assertFalse(flags.reportableFlag)
        flags.reportableFlag = True
        self.assertTrue(flags.reportableFlag)

if __name__ == "__main__":
    unittest.main()
