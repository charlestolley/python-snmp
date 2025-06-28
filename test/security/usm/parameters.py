__all__ = ["SignedUsmParametersTest", "UnsignedUsmParametersTest"]

import unittest

from snmp.ber import EnhancedParseError
from snmp.security.usm.parameters import *
from snmp.utils import subbytes

class SignedUsmParametersTest(unittest.TestCase):
    def setUp(self):
        self.message = bytes.fromhex(
            "30 81 97"
            "   02 01 03"
            "   30 10"
            "      02 04 28 6e 48 41"
            "      02 02 05 dc"
            "      04 01 03"
            "      02 01 03"
            "   04 2e"
            "      30 2c"
            "         04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44"
            "         02 02 05 d4"
            "         02 02 14 d0"
            "         04 08 73 6f 6d 65 55 73 65 72"
            "         04 02 9a 00"
            "         04 04 73 61 6c 74"
            "   04 50"
            "      30 4e"
            "         04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44"
            "         04 00"
            "         a2 3a"
            "            02 04 26 cf 6e 26"
            "            02 01 00"
            "            02 01 00"
            "            30 2c"
            "               30 2a"
            "                  06 07 2b 06 01 02 01 01 00"
            "                  04 1f 54 68 69 73 20 73 74 72 69 6e 67"
            "                        20 64 65 73 63 72 69 62 65 73 20"
            "                        6d 79 20 73 79 73 74 65 6d"
        )

        self.encoding = subbytes(self.message, 26, 72)

        self.engineID = b"remoteEngineID"
        self.engineBoots = 1492
        self.engineTime = 5328
        self.userName = b"someUser"
        self.signature = b"\x9a\x00"
        self.salt = b"salt"

        self.securityParameters = SignedUsmParameters(
            self.engineID,
            self.engineBoots,
            self.engineTime,
            self.userName,
            self.signature,
            self.salt,
        )

    def test_constructor_raises_ValueError_for_negative_engineBoots(self):
        self.assertRaises(
            ValueError,
            SignedUsmParameters,
            self.engineID,
            -1,
            self.engineTime,
            self.userName,
            self.signature,
            self.salt,
        )

    def test_constructor_raises_ValueError_for_negative_engineTime(self):
        self.assertRaises(
            ValueError,
            SignedUsmParameters,
            self.engineID,
            self.engineBoots,
            -1,
            self.userName,
            self.signature,
            self.salt,
        )

    def test_decode_raises_ParseError_for_negative_engineBoots(self):
        encoding = bytes.fromhex(
            "30 10"
            "   04 01 80"
            "   02 01 ff"
            "   02 01 00"
            "   04 01 71"
            "   04 00"
            "   04 00"
        )

        try:
            SignedUsmParameters.decode(encoding)
        except EnhancedParseError as err:
            self.assertEqual(err.data, subbytes(encoding, 5, 8))
        else:
            raise AssertionError("EnhancedParseError not raised by decode")

    def test_decode_raises_ParseError_for_negative_engineTime(self):
        encoding = bytes.fromhex(
            "30 10"
            "   04 01 80"
            "   02 01 00"
            "   02 01 ff"
            "   04 01 71"
            "   04 00"
            "   04 00"
        )

        try:
            SignedUsmParameters.decode(encoding)
        except EnhancedParseError as err:
            self.assertEqual(err.data, subbytes(encoding, 8, 11))
        else:
            raise AssertionError("EnhancedParseError not raised by decode")

    def test_decode_raises_ParseError_for_long_userName(self):
        encoding = bytes.fromhex(
            "30 30"
            "   04 01 80"
            "   02 01 00"
            "   02 01 00"
            "   04 21 00 01 02 03 04 05 06 07"
            "         08 09 0a 0b 0c 0d 0e 0f"
            "         10 11 12 13 14 15 16 17"
            "         18 19 1a 1b 1c 1d 1e 1f 20"
            "   04 00"
            "   04 00"
        )

        try:
            SignedUsmParameters.decode(encoding)
        except EnhancedParseError as err:
            self.assertEqual(err.data, subbytes(encoding, 11, 46))
        else:
            raise AssertionError("EnhancedParseError not raised by decode")

    def test_decode_all_six_fields_defined_in_RFC3414(self):
        params = SignedUsmParameters.decodeExact(self.encoding)
        self.assertEqual(params.engineID, self.engineID)
        self.assertEqual(params.engineBoots, self.engineBoots)
        self.assertEqual(params.engineTime, self.engineTime)
        self.assertEqual(params.userName, self.userName)
        self.assertEqual(params.signature, self.signature)
        self.assertEqual(params.salt, self.salt)

    def test_encode_all_six_fields_defined_in_RFC3414(self):
        self.assertEqual(self.securityParameters.encode(), self.encoding)

    def test_two_objects_with_the_six_equal_fields_are_equal(self):
        self.assertEqual(
            SignedUsmParameters.decode(self.encoding),
            SignedUsmParameters.decode(self.encoding),
        )

    def test_the_result_of_eval_repr_equals_the_original_object(self):
        self.assertEqual(
            eval(repr(self.securityParameters)),
            self.securityParameters,
        )

    def test_decode_preserves_reference_to_wholeMsg(self):
        params = SignedUsmParameters.decodeExact(self.encoding)
        self.assertIs(params.signature.data, self.message)

    def test__str__is_not_the_same_as__repr__(self):
        self.assertNotEqual(
            str(self.securityParameters),
            repr(self.securityParameters),
        )

class UnsignedUsmParametersTest(unittest.TestCase):
    def setUp(self):
        self.message = bytes.fromhex(
            "30 81 97"
            "   02 01 03"
            "   30 10"
            "      02 04 28 6e 48 41"
            "      02 02 05 dc"
            "      04 01 03"
            "      02 01 03"
            "   04 2e"
            "      30 2c"
            "         04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44"
            "         02 02 05 d4"
            "         02 02 14 d0"
            "         04 08 73 6f 6d 65 55 73 65 72"
            "         04 02 00 00"
            "         04 04 73 61 6c 74"
            "   04 50"
            "      30 4e"
            "         04 0e 72 65 6d 6f 74 65 45 6e 67 69 6e 65 49 44"
            "         04 00"
            "         a2 3a"
            "            02 04 26 cf 6e 26"
            "            02 01 00"
            "            02 01 00"
            "            30 2c"
            "               30 2a"
            "                  06 07 2b 06 01 02 01 01 00"
            "                  04 1f 54 68 69 73 20 73 74 72 69 6e 67"
            "                        20 64 65 73 63 72 69 62 65 73 20"
            "                        6d 79 20 73 79 73 74 65 6d"
        )

        self.encoding = subbytes(self.message, 26, 72)

        self.engineID = b"remoteEngineID"
        self.engineBoots = 1492
        self.engineTime = 5328
        self.userName = b"someUser"
        self.padding = b"\x00\x00"
        self.salt = b"salt"

        self.securityParameters = UnsignedUsmParameters(
            self.engineID,
            self.engineBoots,
            self.engineTime,
            self.userName,
            self.padding,
            self.salt,
        )

    def test_constructor_raises_ValueError_for_negative_engineBoots(self):
        self.assertRaises(
            ValueError,
            UnsignedUsmParameters,
            self.engineID,
            -1,
            self.engineTime,
            self.userName,
            self.padding,
            self.salt,
        )

    def test_constructor_raises_ValueError_for_negative_engineTime(self):
        self.assertRaises(
            ValueError,
            UnsignedUsmParameters,
            self.engineID,
            self.engineBoots,
            -1,
            self.userName,
            self.padding,
            self.salt,
        )

    def test_decode_raises_ParseError_for_negative_engineBoots(self):
        encoding = bytes.fromhex(
            "30 10"
            "   04 01 80"
            "   02 01 ff"
            "   02 01 00"
            "   04 01 71"
            "   04 00"
            "   04 00"
        )

        try:
            UnsignedUsmParameters.decode(encoding)
        except EnhancedParseError as err:
            self.assertEqual(err.data, subbytes(encoding, 5, 8))
        else:
            raise AssertionError("EnhancedParseError not raised by decode")

    def test_decode_raises_ParseError_for_negative_engineTime(self):
        encoding = bytes.fromhex(
            "30 10"
            "   04 01 80"
            "   02 01 00"
            "   02 01 ff"
            "   04 01 71"
            "   04 00"
            "   04 00"
        )

        try:
            UnsignedUsmParameters.decode(encoding)
        except EnhancedParseError as err:
            self.assertEqual(err.data, subbytes(encoding, 8, 11))
        else:
            raise AssertionError("EnhancedParseError not raised by decode")

    def test_decode_raises_ParseError_for_long_userName(self):
        encoding = bytes.fromhex(
            "30 30"
            "   04 01 80"
            "   02 01 00"
            "   02 01 00"
            "   04 21 00 01 02 03 04 05 06 07"
            "         08 09 0a 0b 0c 0d 0e 0f"
            "         10 11 12 13 14 15 16 17"
            "         18 19 1a 1b 1c 1d 1e 1f 20"
            "   04 00"
            "   04 00"
        )

        try:
            UnsignedUsmParameters.decode(encoding)
        except EnhancedParseError as err:
            self.assertEqual(err.data, subbytes(encoding, 11, 46))
        else:
            raise AssertionError("EnhancedParseError not raised by decode")

    def test_decode_all_six_fields_defined_in_RFC3414(self):
        params = UnsignedUsmParameters.decodeExact(self.encoding)
        self.assertEqual(params.engineID, self.engineID)
        self.assertEqual(params.engineBoots, self.engineBoots)
        self.assertEqual(params.engineTime, self.engineTime)
        self.assertEqual(params.userName, self.userName)
        self.assertEqual(params.padding, self.padding)
        self.assertEqual(params.salt, self.salt)

    def test_encode_all_six_fields_defined_in_RFC3414(self):
        self.assertEqual(self.securityParameters.encode(), self.encoding)

    def test_two_objects_with_the_six_equal_fields_are_equal(self):
        self.assertEqual(
            UnsignedUsmParameters.decode(self.encoding),
            UnsignedUsmParameters.decode(self.encoding),
        )

    def test_the_result_of_eval_repr_equals_the_original_object(self):
        self.assertEqual(
            eval(repr(self.securityParameters)),
            self.securityParameters,
        )

    def test_findPadding_returns_signature_as_subbytes(self):
        padding = UnsignedUsmParameters.findPadding(self.encoding)
        self.assertEqual(padding, self.encoding[38:40])
        self.assertIs(padding.data, self.message)

    def test__str__is_not_the_same_as__repr__(self):
        self.assertNotEqual(
            str(self.securityParameters),
            repr(self.securityParameters),
        )

if __name__ == "__main__":
    unittest.main()
