__all__ = ["VersionOnlyMessageTest"]

import random
import unittest

from snmp.exception import *
from snmp.message.version import *

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
            prefix = VersionOnlyMessage.decodeExact(message)
            self.assertEqual(version, prefix.version)

    def test_decode_raises_BadVersion_for_unknown_version(self):
        message = bytes.fromhex("30 03 02 01 02")
        self.assertRaises(BadVersion, VersionOnlyMessage.decodeExact, message)

    def test_decode_ignores_everything_after_version_field(self):
        encoding = bytes.fromhex("30 10 02 01 00")
        garbage = bytes([random.randint(0,255) for _ in range(13)])
        VersionOnlyMessage.decodeExact(encoding + garbage)

if __name__ == "__main__":
    unittest.main()
