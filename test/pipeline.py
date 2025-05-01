__all__ = ["VersionDecoderTest"]

import unittest
import weakref

from snmp.exception import *
from snmp.message import *
from snmp.pipeline import *

class VersionDecoderTest(unittest.TestCase):
    class Listener:
        def __init__(self):
            self.messages = []

        def hear(self, data, channel):
            self.messages.append(data)

    def test_hear_ignores_messages_with_no_matching_listener(self):
        decoder = VersionDecoder()
        self.assertRaises(
            BadVersion,
            decoder.hear,
            b"\x30\x03\x02\x01\x00",
            None,
        )

    def test_register_keeps_only_the_first_listener_and_returns_bool(self):
        s1 = self.Listener()
        s2 = self.Listener()

        decoder = VersionDecoder()
        version = ProtocolVersion.SNMPv1
        self.assertTrue(decoder.register(version, s1))
        self.assertFalse(decoder.register(version, s2))

        decoder.hear(b"\x30\x03\x02\x01\x00", None)
        self.assertGreater(len(s1.messages), 0)
        self.assertEqual(len(s2.messages), 0)

    def test_hear_forwards_messages_only_to_the_correct_listener(self):
        v1_message = b"\x30\x18\x02\x01\x00therestisnotimportant"
        v2c_message = b"\x30\x18\x02\x01\x01therestisnotimportant"

        v1_listener = self.Listener()
        v2c_listener = self.Listener()
        decoder = VersionDecoder()
        decoder.register(ProtocolVersion.SNMPv1, v1_listener)
        decoder.register(ProtocolVersion.SNMPv2c, v2c_listener)

        decoder.hear(v1_message, None)
        decoder.hear(v2c_message, None)

        self.assertEqual(v1_listener.messages, [v1_message])
        self.assertEqual(v2c_listener.messages, [v2c_message])

    def test_decoder_does_not_own_listeners(self):
        canary = self.Listener()
        listener = self.Listener()

        reference = weakref.ref(listener)
        canary_reference = weakref.ref(canary)

        decoder = VersionDecoder()
        version = ProtocolVersion.SNMPv1
        decoder.register(version, listener)

        del listener
        del canary

        if canary_reference() is not None:
            self.skipTest("Listener was not immediately destroyed")

        self.assertIsNone(reference())
        self.assertTrue(decoder.register(version, self.Listener()))

if __name__ == "__main__":
    unittest.main()
