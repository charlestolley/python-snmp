__all__ = ["MessageTest", "MessageVersionTest"]

import re
import unittest

from snmp.ber import *
from snmp.smi import *
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
        self.assertRaises(BadVersion, MessageVersion.decode, msg)

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

class MessageTest(unittest.TestCase):
    def setUp(self):
        self.types = {GetRequestPDU.TAG: GetRequestPDU}
        self.template = re.sub(r"\n", "", """
            30 2f
               02 01 {:02x}
               04 0d 74 65 73 74 43 6f 6d 6d 75 6e 69 74 79
               a0 1b
                  02 04 78 9a bc de
                  02 01 00
                  02 01 00
                  30 0d
                     30 0b
                        06 07 2b 06 01 02 01 01 00
                        05 00
        """)

        self.message = Message(
            MessageProcessingModel.SNMPv1,
            b"testCommunity",
            GetRequestPDU("1.3.6.1.2.1.1.0", requestID=0x789abcde),
        )

    def testSNMPv1Message(self):
        version = MessageProcessingModel.SNMPv1
        encoding = bytes.fromhex(self.template.format(version))
        self.message.version = version

        message = Message.decode(encoding, types=self.types)
        self.assertEqual(message, self.message)

    def testSNMPv2cMessage(self):
        version = MessageProcessingModel.SNMPv2c
        encoding = bytes.fromhex(self.template.format(version))
        self.message.version = version

        message = Message.decode(encoding, types=self.types)
        self.assertEqual(message, self.message)

    def testSNMPv3Message(self):
        version = MessageProcessingModel.SNMPv3
        encoding = bytes.fromhex(self.template.format(version))
        self.message.version = version

        self.assertRaises(
            BadVersion,
            Message.decode,
            encoding,
            types=self.types,
        )

    def testInvalidType(self):
        version = MessageProcessingModel.SNMPv1
        encoding = bytes.fromhex(self.template.format(version))
        self.message.version = version

        self.assertRaises(
            ParseError,
            Message.decode,
            encoding,
        )

    def testRepr(self):
        self.assertEqual(eval(repr(self.message)), self.message)

    def testEncode(self):
        version = MessageProcessingModel.SNMPv1
        encoding = bytes.fromhex(self.template.format(version))
        self.message.version = version

        self.assertEqual(self.message.encode(), encoding)

if __name__ == "__main__":
    unittest.main()
