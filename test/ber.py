__all__ = [
    "DecodeTest", "DecodeLengthTest", "EncodeTest",
    "EncodeLengthTest", "ExceptionTypesTest", "TagTest",
]

import unittest
from snmp.ber import *
from snmp.ber import decode_length, encode_length
from snmp.exception import *
from snmp.utils import subbytes

class ExceptionTypesTest(unittest.TestCase):
    def test_EncodeError_subclasses_SNMPException(self):
        self.assertIsInstance(EncodeError(), SNMPException)

    def test_ParseError_subclasses_IncomingMessageError(self):
        self.assertIsInstance(ParseError(), IncomingMessageError)

class TagTest(unittest.TestCase):
    def test_decode_raises_ParseError_on_empty_input(self):
        self.assertRaises(ParseError, Tag.decode, subbytes(b""))

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        tag = Tag(14, True, Tag.Class.CONTEXT_SPECIFIC)
        self.assertEqual(eval(repr(tag)), tag)

    def test_decode_extracts_class_from_two_most_significant_bits(self):
        for encoding, cls in (
            (b"\x00", Tag.Class.UNIVERSAL),
            (b"\x40", Tag.Class.APPLICATION),
            (b"\x80", Tag.Class.CONTEXT_SPECIFIC),
            (b"\xc0", Tag.Class.PRIVATE),
        ):
            tag, _ = Tag.decode(subbytes(encoding))
            self.assertEqual(tag.cls, cls)
            self.assertEqual(tag.constructed, 0)
            self.assertEqual(tag.number, 0)

    def test_encode_packs_class_into_the_two_most_significant_bits(self):
        for encoding, cls in (
            (b"\x00", Tag.Class.UNIVERSAL),
            (b"\x40", Tag.Class.APPLICATION),
            (b"\x80", Tag.Class.CONTEXT_SPECIFIC),
            (b"\xc0", Tag.Class.PRIVATE),
        ):
            tag = Tag(0, 0, cls)
            self.assertEqual(tag.encode(), encoding)

    def test_decode_extracts_constructed_from_bit_five(self):
        for encoding, constructed in (
            (b"\x00", False),
            (b"\x20", True),
        ):
            tag, _ = Tag.decode(subbytes(encoding))
            self.assertEqual(tag.cls, 0)
            self.assertEqual(tag.constructed, constructed)
            self.assertEqual(tag.number, 0)

    def test_encode_packs_constructed_into_bit_five(self):
        for encoding, constructed in (
            (b"\x00", False),
            (b"\x20", True),
        ):
            tag = Tag(0, constructed, 0)
            self.assertEqual(tag.encode(), encoding)

    def test_decode_extracts_tag_from_five_least_significant_bits(self):
        for n in range(0, 31):
            encoding = n.to_bytes(1, "little")
            tag, _ = Tag.decode(subbytes(encoding))
            self.assertEqual(tag.cls, 0)
            self.assertEqual(tag.constructed, 0)
            self.assertEqual(tag.number, n)

    def test_encode_packs_tag_into_five_least_significant_bits(self):
        for n in range(0, 31):
            encoding = n.to_bytes(1, "little")
            tag = Tag(n, 0, 0)
            self.assertEqual(tag.encode(), encoding)
        
    def test_decode_raises_ParseError_when_extended_tag_is_missing(self):
        self.assertRaises(ParseError, Tag.decode, subbytes(b"\x1f"))

    def test_decode_understands_extended_tags(self):
        encoding = subbytes(b"\x1f\x88\xdc\x7b\x01\x00")
        tag, encoding = Tag.decode(encoding)
        self.assertEqual(tag.number, 0x022e7b)
        self.assertEqual(len(encoding), 2)

    def test_encode_uses_extended_tag_rules_for_tags_over_31(self):
        tag = Tag(32, 0, 0)
        self.assertEqual(tag.encode(), b"\x1f\x20")

        tag = Tag(0x022e7b, 0, 0)
        self.assertEqual(tag.encode(), b"\x1f\x88\xdc\x7b")

    def test_decode_does_not_modify_the_data_argument(self):
        encoding = subbytes(b"\x02\x01\x00")
        copy = encoding[:]
        tag, data = Tag.decode(encoding)
        self.assertEqual(encoding, copy)

class DecodeLengthTest(unittest.TestCase):
    def setUp(self):
        self.payload = b"payload"

    def test_raises_ParseError_when_encoding_is_empty(self):
        self.assertRaises(ParseError, decode_length, subbytes(b""))

    def test_raises_ParseError_when_msb_is_set_but_encoding_is_too_short(self):
        self.assertRaises(ParseError, decode_length, subbytes(b"\x81"))
        self.assertRaises(ParseError, decode_length, subbytes(b"\x82\x01"))

    def test_returns_zero_when_msb_is_set_and_seven_lsb_are_zero(self):
        encoding = subbytes(b"\x80")
        length, _ = decode_length(encoding)
        self.assertEqual(length, 0)

    def test_returns_the_first_byte_when_msb_is_not_set(self):
        for length in range(127):
            encoding = subbytes(length.to_bytes(1, "little"))
            self.assertEqual(decode_length(encoding)[0], length)

    def test_concatenates_all_bytes_of_long_form_length_encoding(self):
        encoding = subbytes(b"\x84\x12\x34\x56\x78")
        length, _ = decode_length(encoding)
        self.assertEqual(length, 0x12345678)

    def test_treats_length_as_unsigned(self):
        encoding = subbytes(b"\x81\x80")
        length, _ = decode_length(encoding)
        self.assertGreaterEqual(length, 0)

    def test_advances_one_byte_when_msb_is_not_set(self):
        encoding = subbytes(b"\x07" + self.payload)
        _, encoding = decode_length(encoding)
        self.assertEqual(encoding, self.payload)

    def test_advances_over_all_bytes_of_long_form_length_encoding(self):
        encoding = subbytes(b"\x84\x12\x34\x56\x78" + self.payload)
        _, encoding = decode_length(encoding)
        self.assertEqual(encoding, self.payload)

    def test_accepts_maximum_length_encodings(self):
        encoding = subbytes(b"\xff" + (b"\xff" * 0x7f))
        length, encoding = decode_length(encoding)
        self.assertEqual(len(encoding), 0)

class EncodeLengthTest(unittest.TestCase):
    def test_encodes_numbers_below_128_as_a_single_byte(self):
        for i in range(128):
            encoding = encode_length(i)
            self.assertEqual(encoding, i.to_bytes(1, "little"))

    def test_encodes_numbers_between_128_and_255_as_two_bytes(self):
        for i in range(128, 256):
            encoding = encode_length(i)
            self.assertEqual(encoding, b"\x81" + i.to_bytes(1, "little"))

    def test_encodes_multi_byte_lengths_as_big_endian(self):
        length = 0x12345678
        encoding = encode_length(length)
        self.assertEqual(encoding, b"\x84\x12\x34\x56\x78")

    def test_raises_EncodeError_when_length_is_too_big(self):
        length = 1 << (0x7f * 8)
        self.assertRaises(EncodeError, encode_length, length)

    def test_successfully_encodes_maximum_length_value(self):
        length = (1 << (0x7f * 8)) - 1
        result = encode_length(length)
        self.assertEqual(result, b"\xff" + (b"\xff" * 0x7f))

class DecodeTest(unittest.TestCase):
    def setUp(self):
        self.data = b"\x04\x02\x00\x00"
        self.extra = b"this string contains nothing but leftovers"
        self.tag = Tag(4, False, Tag.Class.UNIVERSAL)
        self.payload = self.data[2:]

    def test_returns_tag_when_expected_is_None(self):
        result = decode(self.data)
        self.assertIsInstance(result, tuple)
        self.assertEqual(result[0], self.tag)

    def test_does_not_return_tag_when_type_matches_expected(self):
        result = decode(self.data, expected=self.tag)
        self.assertNotIsInstance(result, tuple)
        self.assertNotIsInstance(result, Tag)

    def test_raises_ParseError_when_type_does_not_match_expected(self):
        expected = Tag(
            self.tag.number + 1,
            self.tag.constructed,
            self.tag.cls,
        )

        self.assertRaises(ParseError, decode, self.data, expected)

    def test_raises_ParseError_when_payload_is_too_short(self):
        self.assertRaises(ParseError, decode, self.data[:-1])

    def test_raises_ParseError_when_there_are_unexpected_leftovers(self):
        self.assertRaises(ParseError, decode, self.data + self.extra)

    def test_returns_trailing_bytes_when_leftovers_is_True(self):
        _, leftovers = decode(
            self.data + self.extra,
            self.tag,
            leftovers=True,
        )

        self.assertEqual(leftovers, self.extra)

    def test_returns_leftovers_as_subbytes(self):
        _, leftovers = decode(
            self.data + self.extra,
            self.tag,
            leftovers=True,
        )

        self.assertIsInstance(leftovers, subbytes)

    def test_returns_empty_leftovers_if_data_was_fully_consumed(self):
        _, leftovers = decode(self.data, self.tag, leftovers=True)
        self.assertEqual(leftovers, bytes())

    def test_returns_raw_data_when_copy_is_True(self):
        payload = decode(self.data, self.tag, copy=True)
        self.assertNotIsInstance(payload, subbytes)

    def test_returns_subbytes_referencing_data_when_copy_is_False(self):
        payload = decode(self.data, self.tag, copy=False)
        self.assertIsInstance(payload, subbytes)
        self.assertIs(payload.data, self.data)

    def test_return_type_not_affected_by_the_type_of_the_data_argument(self):
        for data in (self.data, subbytes(self.data)):
            payload = decode(data, self.tag, copy=True)
            self.assertNotIsInstance(payload, subbytes)

            payload = decode(data, self.tag, copy=False)
            self.assertIsInstance(payload, subbytes)

class EncodeTest(unittest.TestCase):
    def test_concatenates_tag_and_length_encoding_with_payload(self):
        encoding = encode(
            Tag(4, False, Tag.Class.UNIVERSAL),
            b"payload string",
        )

        self.assertEqual(encoding, b"\x04\x0epayload string")

if __name__ == '__main__':
    unittest.main()
