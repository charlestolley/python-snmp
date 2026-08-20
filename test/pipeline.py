__all__ = ["CatcherTest", "VersionDecoderTest"]

import gc
import unittest
import weakref

from snmp.exception import *
from snmp.message import *
from snmp.pipeline import *
from snmp.utils import *

class CatcherTest(unittest.TestCase):
    class Listener:
        def __init__(self, exc=None):
            self.channel = None
            self.data = None
            self.exception = exc

        def hear(self, data, channel):
            if self.exception is not None:
                raise self.exception
            else:
                self.channel = channel
                self.data = data

    class Logger:
        def __init__(self):
            self.exc = None
            self.msg = None

        def debug(self, msg):
            self.msg = msg

        def exception(self, exc):
            self.exc = exc

    def test_hear_forwards_arguments_to_listener(self):
        listener = self.Listener()
        catcher = Catcher(listener)
        catcher.hear(b"asdf", 28)
        self.assertEqual(listener.data, b"asdf")
        self.assertEqual(listener.channel, 28)

    def test_packets_counts_the_number_of_calls_to_hear(self):
        listener = self.Listener()
        catcher = Catcher(listener)

        for i in range(36):
            catcher.hear(b"asdf", 37)

        self.assertEqual(catcher.packets, 36)

    def test_packets_counts_calls_resulting_in_an_exception(self):
        exc = RuntimeError("That's not good...")
        listener = self.Listener(exc)
        logger = self.Logger()
        catcher = Catcher(listener)
        catcher.logger = logger

        self.assertEqual(catcher.packets, 0)
        self.assertIsNone(logger.exc)
        catcher.hear(b"asdf", 59)
        self.assertIs(logger.exc, exc)
        self.assertEqual(catcher.packets, 1)

    def test_hear_catches_and_logs_generic_Exception(self):
        listener = self.Listener(Exception("A generic exception"))
        logger = self.Logger()
        catcher = Catcher(listener)
        catcher.logger = logger

        self.assertIsNone(logger.exc)
        catcher.hear(b"asdf", 70)
        self.assertIsInstance(logger.exc, Exception)

    def test_hear_discards_IncomingMesageError_if_not_verbose(self):
        listener = self.Listener(IncomingMessageError("Invalid message"))
        logger = self.Logger()
        catcher = Catcher(listener)
        catcher.logger = logger

        catcher.hear(b"asdf", 81)
        self.assertIsNone(logger.msg)

    def test_hear_logs_IncomingMesageError_if_verbose(self):
        listener = self.Listener(IncomingMessageError("Invalid message"))
        logger = self.Logger()
        catcher = Catcher(listener, verbose=True)
        catcher.logger = logger

        catcher.hear(b"asdf", 90)
        self.assertIsNotNone(logger.msg)
        self.assertIn("Invalid message", logger.msg)

    def test_hear_discards_IncomingMesageErrorWithPointer_if_not_verbose(self):
        data = b"asdf"
        ptr = subbytes(data, 1)
        exc = IncomingMessageErrorWithPointer("Invalid message", ptr)
        listener = self.Listener(exc)
        logger = self.Logger()
        catcher = Catcher(listener)
        catcher.logger = logger

        catcher.hear(b"asdf", 103)
        self.assertIsNone(logger.msg)

    def test_hear_logs_IncomingMesageErrorWithPointer_if_verbose(self):
        data = b"asdf"
        ptr = subbytes(data, 1)
        exc = IncomingMessageErrorWithPointer("Invalid message", ptr)
        listener = self.Listener(exc)
        logger = self.Logger()
        catcher = Catcher(listener, verbose=True)
        catcher.logger = logger

        catcher.hear(b"asdf", 115)
        self.assertIsNotNone(logger.msg)
        self.assertIn("Invalid message", logger.msg)
        self.assertIn("73 64 66", logger.msg)

class VersionDecoderTest(unittest.TestCase):
    class Listener:
        def __init__(self):
            self.messages = []

        def hear(self, data, channel):
            self.messages.append(data)

    def test_hear_ignores_messages_with_no_matching_listener(self):
        message = b"\x30\x03\x02\x01\x00"
        decoder = VersionDecoder()

        try:
            decoder.hear(message, None)
        except BadVersion as err:
            self.assertEqual(err.data, message)
        else:
            raise AssertionError("BadVersion not raised by hear")

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
        listener = self.Listener()
        reference = weakref.ref(listener)

        decoder = VersionDecoder()
        version = ProtocolVersion.SNMPv1
        decoder.register(version, listener)

        del listener
        gc.collect()

        self.assertIsNone(reference())
        self.assertTrue(decoder.register(version, self.Listener()))

if __name__ == "__main__":
    unittest.main()
