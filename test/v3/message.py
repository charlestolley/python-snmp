__all__ = ["HeaderDataTest", "MessageFlagsTest"]

import unittest

from snmp.ber import ParseError
from snmp.exception import *
from snmp.security import *
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

class HeaderDataTest(unittest.TestCase):
    def setUp(self):
        self.encoding = bytes.fromhex(
            "30 10                  "   # SEQUENCE
            "   02 04 17 39 27 45   "   #   0x17392745
            "   02 02 05 dc         "   #   1500
            "   04 01 07            "   #   AUTH | PRIV | REPORTABLE
            "   02 01 03            "   #   USM
        )

        self.header = HeaderData(
            0x17392745,
            1500,
            MessageFlags(authPriv, True),
            SecurityModel.USM,
        )

    def test_constructor_raises_ValueError_if_msgID_is_negative(self):
        self.assertRaises(
            ValueError,
            HeaderData,
            -1,
            1500,
            MessageFlags(authPriv, True),
            SecurityModel.USM,
        )

    def test_constructor_raises_ValueError_if_msgID_is_over_int32_max(self):
        self.assertRaises(
            ValueError,
            HeaderData,
            1 << 31,
            1500,
            MessageFlags(authPriv, True),
            SecurityModel.USM,
        )

    def test_constructor_raises_ValueError_if_maxSize_is_less_than_484(self):
        self.assertRaises(
            ValueError,
            HeaderData,
            0x17392745,
            483,
            MessageFlags(authPriv, True),
            SecurityModel.USM,
        )

    def test_constructor_raises_ValueError_if_maxSize_is_over_int32_max(self):
        self.assertRaises(
            ValueError,
            HeaderData,
            0x17392745,
            1 << 31,
            MessageFlags(authPriv, True),
            SecurityModel.USM,
        )

    def test_constructor_accepts_msdID_of_0_and_int32_max(self):
        flags = MessageFlags(authPriv, True)
        HeaderData(0, 1500, flags, SecurityModel.USM)
        HeaderData((1 << 31) - 1, 1500, flags, SecurityModel.USM)

    def test_constructor_accepts_maxSize_of_484_and_int32_max(self):
        flags = MessageFlags(authPriv, True)
        HeaderData(0x17392745, 484, flags, SecurityModel.USM)
        HeaderData(0x17392745, (1 << 31) - 1, flags, SecurityModel.USM)

    def test_decode_raises_ParseError_if_msgID_is_negative(self):
        invalid = bytes.fromhex(
            "30 10"
            "   02 04 ff ff ff ff"
            "   02 02 05 dc"
            "   04 01 07"
            "   02 01 03"
        )

        self.assertRaises(ParseError, HeaderData.decode, invalid)

    def test_decode_raises_ParseError_if_msgID_is_over_int32_max(self):
        invalid = bytes.fromhex(
            "30 11"
            "   02 05 00 80 00 00 00"
            "   02 02 05 dc"
            "   04 01 07"
            "   02 01 03"
        )

        self.assertRaises(ParseError, HeaderData.decode, invalid)

    def test_decode_raises_ParseError_if_maxSize_is_less_than_484(self):
        invalid = bytes.fromhex(
            "30 10"
            "   02 04 17 39 27 45"
            "   02 02 01 e3"
            "   04 01 07"
            "   02 01 03"
        )

        self.assertRaises(ParseError, HeaderData.decode, invalid)

    def test_decode_raises_ParseError_if_maxSize_is_over_int32_max(self):
        invalid = bytes.fromhex(
            "30 13"
            "   02 04 17 39 27 45"
            "   02 05 00 80 00 00 00"
            "   04 01 07"
            "   02 01 03"
        )

        self.assertRaises(ParseError, HeaderData.decode, invalid)

    def test_decode_accepts_msdID_of_0_and_int32_max(self):
        HeaderData.decode(bytes.fromhex(
            "30 0d"
            "   02 01 00"
            "   02 02 05 dc"
            "   04 01 07"
            "   02 01 03"
        ))

        HeaderData.decode(bytes.fromhex(
            "30 11"
            "   02 05 00 7f ff ff ff"
            "   02 02 05 dc"
            "   04 01 07"
            "   02 01 03"
        ))

    def test_decode_raises_ParseError_if_securityModel_is_less_than_1(self):
        invalid = bytes.fromhex(
            "30 10"
            "   02 04 17 39 27 45"
            "   02 02 05 dc"
            "   04 01 07"
            "   02 01 00"
        )

        self.assertRaises(ParseError, HeaderData.decode, invalid)

        invalid = bytes.fromhex(
            "30 10"
            "   02 04 17 39 27 45"
            "   02 02 05 dc"
            "   04 01 07"
            "   02 01 ff"
        )

        self.assertRaises(ParseError, HeaderData.decode, invalid)

    def test_decode_raises_ParseError_if_securityModel_is_over_int32_max(self):
        invalid = bytes.fromhex(
            "30 14"
            "   02 04 17 39 27 45"
            "   02 02 05 dc"
            "   04 01 07"
            "   02 05 00 80 00 00 00"
        )

        self.assertRaises(ParseError, HeaderData.decode, invalid)

    def test_decode_raises_UnknownSecurityModel_if_model_is_not_3(self):
        invalid = bytes.fromhex(
            "30 10"
            "   02 04 17 39 27 45"
            "   02 02 05 dc"
            "   04 01 07"
            "   02 01 01"
        )

        self.assertRaises(UnknownSecurityModel, HeaderData.decode, invalid)

        invalid = bytes.fromhex(
            "30 13"
            "   02 04 17 39 27 45"
            "   02 02 05 dc"
            "   04 01 07"
            "   02 04 7f ff ff ff"
        )

        self.assertRaises(UnknownSecurityModel, HeaderData.decode, invalid)

    def test_decode_accepts_maxSize_of_484_and_int32_max(self):
        HeaderData.decode(bytes.fromhex(
            "30 10"
            "   02 04 17 39 27 45"
            "   02 02 01 e4"
            "   04 01 07"
            "   02 01 03"
        ))

        HeaderData.decode(bytes.fromhex(
            "30 12"
            "   02 04 17 39 27 45"
            "   02 04 7f ff ff ff"
            "   04 01 07"
            "   02 01 03"
        ))

    def test_fields_have_the_expected_names(self):
        header = HeaderData(
            0x17392745,
            1500,
            MessageFlags(authPriv, True),
            SecurityModel.USM,
        )

        self.assertEqual(header.id, 0x17392745)
        self.assertEqual(header.maxSize, 1500)
        self.assertTrue(header.flags.authFlag)
        self.assertEqual(header.securityModel, SecurityModel.USM)

    def test_decode_example_matches_the_hand_computed_result(self):
        self.assertEqual(HeaderData.decodeExact(self.encoding), self.header)

    def test_encode_example_matches_the_hand_computed_result(self):
        self.assertEqual(self.header.encode(), self.encoding)

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        self.assertEqual(eval(repr(self.header)), self.header)

if __name__ == "__main__":
    unittest.main()
