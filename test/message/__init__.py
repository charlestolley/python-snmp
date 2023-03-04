__all__ = ["MessageVersionTest"]

import unittest

from snmp.ber import *
from snmp.types import *
from snmp.pdu import *
from snmp.message import *

class MessageVersionTest(unittest.TestCase):
    def testSNMPv1(self):
        msg = bytes.fromhex("30 03 02 01 00")
        msgVersion = MessageVersion.decode(msg)
        self.assertEqual(msgVersion.version, MessageProcessingModel.SNMPv1)

    def testSNMPv2c(self):
        msg = bytes.fromhex("30 03 02 01 01")
        msgVersion = MessageVersion.decode(msg)
        self.assertEqual(msgVersion.version, MessageProcessingModel.SNMPv2c)

    def testSNMPv3(self):
        msg = bytes.fromhex("30 03 02 01 03")
        msgVersion = MessageVersion.decode(msg)
        self.assertEqual(msgVersion.version, MessageProcessingModel.SNMPv3)

    def testBadVersion(self):
        msg = bytes.fromhex("30 03 02 01 02")
        self.assertRaises(ParseError, MessageVersion.decode, msg)

    def testEquality(self):
        msg = bytes.fromhex("30 03 02 01 03")
        self.assertEqual(
            MessageVersion.decode(msg),
            MessageVersion(MessageProcessingModel.SNMPv3),
        )

    def testRepr(self):
        msgVersion = MessageVersion(MessageProcessingModel.SNMPv3)
        duplicate = eval(repr(msgVersion))

        self.assertEqual(duplicate, msgVersion)
        self.assertIsInstance(duplicate.version, MessageProcessingModel)

    def testEncode(self):
        self.assertEqual(
            MessageVersion(MessageProcessingModel.SNMPv3).encode(),
            bytes.fromhex("30 03 02 01 03"),
        )

if __name__ == "__main__":
    unittest.main()
