__all__ = ["MessageFlagsTest"]

import unittest

from snmp.ber import ParseError
from snmp.exception import *
from snmp.security.levels import *
from snmp.v3.message import *

class MessageFlagsTest(unittest.TestCase):
    def test_auth_priv_and_reportable_flags_are_off_by_default(self):
        flags = MessageFlags()
        self.assertFalse(flags.authFlag)
        self.assertFalse(flags.privFlag)
        self.assertFalse(flags.reportableFlag)

    def test_two_objects_with_identical_flags_are_equal(self):
        self.assertEqual(
            MessageFlags(authNoPriv, True),
            MessageFlags(authNoPriv, True),
        )

    def test_two_objects_with_different_flags_are_not_equal(self):
        self.assertNotEqual(MessageFlags(authPriv), MessageFlags(authNoPriv))

    def test_securityLevel_parameter_initializes_auth_and_priv_flags(self):
        flags = MessageFlags(noAuthNoPriv)
        self.assertFalse(flags.authFlag)
        self.assertFalse(flags.privFlag)

        flags = MessageFlags(authNoPriv)
        self.assertTrue(flags.authFlag)
        self.assertFalse(flags.privFlag)

        flags = MessageFlags(authPriv)
        self.assertTrue(flags.authFlag)
        self.assertTrue(flags.privFlag)

    def test_reportable_parameter_initializes_reportableFlag(self):
        flags = MessageFlags(reportable=False)
        self.assertFalse(flags.reportableFlag)

        flags = MessageFlags(reportable=True)
        self.assertTrue(flags.reportableFlag)

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        flags = MessageFlags(authPriv, False),
        self.assertEqual(eval(repr(flags)), flags)

        flags = MessageFlags(authNoPriv, True),
        self.assertEqual(eval(repr(flags)), flags)

        flags = MessageFlags(reportable=True)
        self.assertEqual(eval(repr(flags)), flags)

    def test_decode_produces_all_valid_values(self):
        self.assertEqual(
            MessageFlags.decodeExact(b"\x04\x01\x00"),
            MessageFlags(),
        )

        self.assertEqual(
            MessageFlags.decodeExact(b"\x04\x01\x01"),
            MessageFlags(authNoPriv),
        )

        self.assertEqual(
            MessageFlags.decodeExact(b"\x04\x01\x03"),
            MessageFlags(authPriv),
        )

        self.assertEqual(
            MessageFlags.decodeExact(b"\x04\x01\x04"),
            MessageFlags(reportable=True),
        )

        self.assertEqual(
            MessageFlags.decodeExact(b"\x04\x01\x05"),
            MessageFlags(authNoPriv, reportable=True),
        )

        self.assertEqual(
            MessageFlags.decodeExact(b"\x04\x01\x07"),
            MessageFlags(authPriv, reportable=True),
        )

    def test_decode_raises_ParseError_on_empty_string(self):
        self.assertRaises(ParseError, MessageFlags.decodeExact, b"\x04\x00")

    def test_decode_raises_IncomingMessageError_on_invalid_securityLevel(self):
        self.assertRaises(
            IncomingMessageError,
            MessageFlags.decodeExact,
            b"\x04\x01\x02",
        )

    def test_decode_ignores_extra_bytes(self):
        self.assertEqual(
            MessageFlags.decodeExact(b"\x04\x02\x07\x00"),
            MessageFlags(authPriv, True),
        )

    def test_decode_ignores_extra_bits(self):
        self.assertEqual(
            MessageFlags.decodeExact(b"\x04\x01\x09"),
            MessageFlags(authNoPriv),
        )

    def test_encode(self):
        self.assertEqual(MessageFlags().encode(), b"\x04\x01\x00")
        self.assertEqual(MessageFlags(authNoPriv).encode(), b"\x04\x01\x01")
        self.assertEqual(MessageFlags(authPriv).encode(), b"\x04\x01\x03")

        self.assertEqual(
            MessageFlags(reportable=True).encode(),
            b"\x04\x01\x04",
        )

        self.assertEqual(
            MessageFlags(authNoPriv, reportable=True).encode(),
            b"\x04\x01\x05",
        )

        self.assertEqual(
            MessageFlags(authPriv, reportable=True).encode(),
            b"\x04\x01\x07",
        )

if __name__ == "__main__":
    unittest.main()
