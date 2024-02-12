__all__ = ["VersionOnlyMessageTest", "MessageTest"]

import random
import re
import unittest

from snmp.ber import *
from snmp.smi import *
from snmp.pdu import *
from snmp.message import *

class VersionOnlyMessageTest(unittest.TestCase):
    def setUp(self):
        self.messages = {
            ProtocolVersion.SNMPv1: bytes.fromhex("30 03 02 01 00"),
            ProtocolVersion.SNMPv2c: bytes.fromhex("30 03 02 01 01"),
            ProtocolVersion.SNMPv3: bytes.fromhex("30 03 02 01 03"),
        }

    def test_the_result_of_eval_repr_equals_the_original(self):
        prefix = VersionOnlyMessage(ProtocolVersion.SNMPv3)
        self.assertEqual(eval(repr(prefix)), prefix)

    def test_determines_the_version_of_any_message(self):
        for version, message in self.messages.items():
            prefix = VersionOnlyMessage.decode(message)
            self.assertEqual(version, prefix.version)

    def test_decode_raises_BadVersion_for_unknown_version(self):
        message = bytes.fromhex("30 03 02 01 02")
        self.assertRaises(BadVersion, VersionOnlyMessage.decode, message)

    def test_decode_ignores_everything_after_version_field(self):
        encoding = bytes.fromhex("30 10 02 01 00")
        garbage = bytes([random.randint(0,255) for _ in range(13)])
        VersionOnlyMessage.decode(encoding + garbage)

class MessageTest(unittest.TestCase):
    def setUp(self):
        community = b"testCommunity"
        pdu = GetRequestPDU("1.3.6.1.2.1.1.0", requestID=0x789abcde)

        template = re.sub(r"\n", "", """
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

        self.types = {GetRequestPDU.TAG: GetRequestPDU}
        self.versions = (ProtocolVersion.SNMPv1, ProtocolVersion.SNMPv2c)

        self.encodings = {}
        self.messages = {}

        for version in ProtocolVersion:
            self.encodings[version] = bytes.fromhex(template.format(version))
            self.messages[version] = Message(version, community, pdu)

    def test_two_Messages_with_different_versions_are_not_equal(self):
        self.assertNotEqual(
            self.messages[ProtocolVersion.SNMPv1],
            self.messages[ProtocolVersion.SNMPv2c],
        )

    def test_decode_raises_ParseError_if_the_PDU_tag_is_not_in_types(self):
        for version in self.versions:
            encoding = self.encodings[version]
            self.assertRaises(ParseError, Message.decode, encoding)

    def test_Message_can_decode_SNMPv1_and_SNMPv2c_message(self):
        for version in self.versions:
            encoding = self.encodings[version]
            message = Message.decode(encoding, types=self.types)
            self.assertEqual(message, self.messages[version])

    def test_decode_raises_BadVersion_on_SNMPv3_message(self):
        encoding = self.encodings[ProtocolVersion.SNMPv3]
        self.assertRaises(
            BadVersion,
            Message.decode,
            encoding,
            types=self.types,
        )

    def test_the_result_of_eval_repr_equals_the_original_object(self):
        for version in self.versions:
            message = self.messages[version]
            self.assertEqual(eval(repr(message)), message)

    def test_the_result_of_decode_encode_equals_the_original(self):
        for version in self.versions:
            message = self.messages[version]
            self.assertEqual(
                Message.decode(message.encode(), types=self.types),
                message,
            )

if __name__ == "__main__":
    unittest.main()
