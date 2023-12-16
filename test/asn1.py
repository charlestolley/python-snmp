__all__ = [
    "INTEGERTest", "OCTET_STRINGTest", "NULLTest", "OBJECT_IDENTIFIERTest",
    "SEQUENCETest",
]

import unittest
from snmp.asn1 import *
from snmp.ber import *
from snmp.utils import *

class INTEGERTest(unittest.TestCase):
    def test_tag_universal_primitive_2(self):
        self.assertEqual(INTEGER.TAG.cls, Tag.Class.UNIVERSAL)
        self.assertEqual(INTEGER.TAG.constructed, False)
        self.assertEqual(INTEGER.TAG.number, 2)

    def test_value_is_read_only(self):
        i = INTEGER(3)
        self.assertRaises(AttributeError, setattr, i, "value", 4)

    def test_two_integers_with_the_same_value_are_equal(self):
        i = INTEGER(12)
        j = INTEGER(i.value)
        self.assertEqual(i, j)

    def test_two_integers_with_different_values_are_not_equal(self):
        i = INTEGER(12)
        j = INTEGER(i.value + 1)
        self.assertNotEqual(i, j)

    def test_eval_repr_returns_equivalent_object(self):
        i = INTEGER(65)
        self.assertEqual(eval(repr(i)), i)

    def test_decode_returns_INTEGER(self):
        self.assertIsInstance(INTEGER.decode(b"\x02\x01\x00"), INTEGER)

    def test_decode_uses_big_endian_byte_order(self):
        self.assertEqual(
            INTEGER.decode(b"\x02\x04\x12\x34\x56\x78").value,
            0x12345678,
        )

    def test_encode_uses_big_endian_byte_order(self):
        self.assertEqual(
            INTEGER(0x12345678).encode(),
            b"\x02\x04\x12\x34\x56\x78",
        )

    def test_decode_uses_twos_complement(self):
        self.assertEqual(INTEGER.decode(b"\x02\x01\x80").value, -128)
        self.assertEqual(INTEGER.decode(b"\x02\x02\x00\x80").value, 128)

    def test_encode_produces_the_smallest_twos_complement_encoding(self):
        self.assertEqual(INTEGER(-128).encode(), b"\x02\x01\x80")
        self.assertEqual(INTEGER(-129).encode(), b"\x02\x02\xff\x7f")
        self.assertEqual(INTEGER(128).encode(), b"\x02\x02\x00\x80")

class OCTET_STRINGTest(unittest.TestCase):
    def setUp(self):
        self.payload = b"payload"
        self.encoding = b"\x04\x07" + self.payload

    def test_tag_universal_primitive_4(self):
        self.assertEqual(OCTET_STRING.TAG.cls, Tag.Class.UNIVERSAL)
        self.assertEqual(OCTET_STRING.TAG.constructed, False)
        self.assertEqual(OCTET_STRING.TAG.number, 4)

    def test_data_is_read_only(self):
        s = OCTET_STRING(self.payload)
        self.assertRaises(AttributeError, setattr, s, "data", b"")

    def test_two_strings_with_equal_data_are_equal(self):
        self.assertEqual(OCTET_STRING(b"asdf"), OCTET_STRING(b"asdf"))

    def test_two_strings_with_different_data_are_not_equal(self):
        self.assertNotEqual(OCTET_STRING(b"asdf"), OCTET_STRING(b"fdsa"))

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        s = OCTET_STRING(b"contents")
        self.assertEqual(eval(repr(s)), s)

    def test_constructor_uses_empty_data_by_default(self):
        self.assertEqual(OCTET_STRING().data, b"")

    def test_decoded_object_data_equals_payload(self):
        for copy in (True, False):
            s = OCTET_STRING.decode(self.encoding, copy=copy)
            self.assertEqual(s.data, self.payload)

    def test_encode_uses_data_as_the_payload(self):
        data = b"this is some data"
        encoding = b"\x04" + bytes([len(data)]) + data
        self.assertEqual(OCTET_STRING(data).encode(), encoding)

class NULLTest(unittest.TestCase):
    def test_tag_universal_primitive_5(self):
        self.assertEqual(NULL.TAG.cls, Tag.Class.UNIVERSAL)
        self.assertEqual(NULL.TAG.constructed, False)
        self.assertEqual(NULL.TAG.number, 5)

    def test_two_NULL_objects_are_equal(self):
        self.assertEqual(NULL(), NULL())

    def test_NULL_object_is_not_equal_to_non_NULL_object(self):
        self.assertNotEqual(NULL(), INTEGER(0))

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        null = NULL()
        self.assertEqual(eval(repr(null)), null)

    def test_decode_ignores_payload(self):
        encoding = b"\x05\x02\x12\x34"
        self.assertEqual(NULL.decode(encoding), NULL())

    def test_encode_uses_empty_payload(self):
        self.assertEqual(NULL().encode(), b"\x05\x00")

class OBJECT_IDENTIFIERTest(unittest.TestCase):
    def setUp(self):
        self.internet = OBJECT_IDENTIFIER(1, 3, 6, 1)

    def test_tag_universal_primitive_6(self):
        self.assertEqual(OBJECT_IDENTIFIER.TAG.cls, Tag.Class.UNIVERSAL)
        self.assertEqual(OBJECT_IDENTIFIER.TAG.constructed, False)
        self.assertEqual(OBJECT_IDENTIFIER.TAG.number, 6)

    def test_ValueError_if_the_first_two_subidentifiers_are_too_big(self):
        _ = OBJECT_IDENTIFIER(2, 39)
        self.assertRaises(ValueError, OBJECT_IDENTIFIER, 3, 39)
        self.assertRaises(ValueError, OBJECT_IDENTIFIER, 2, 40)

    def test_two_OIDs_with_equal_subidentifiers_are_equal(self):
        self.assertEqual(
            OBJECT_IDENTIFIER(1, 3, 6, 1),
            OBJECT_IDENTIFIER(1, 3, 6, 1),
        )

    def test_two_OIDs_with_different_subidentifiers_are_not_equal(self):
        self.assertNotEqual(
            OBJECT_IDENTIFIER(1, 3, 6, 1),
            OBJECT_IDENTIFIER(1, 6, 3, 1),
        )

    def test_OID_is_not_equal_to_non_OID(self):
        self.assertNotEqual(OBJECT_IDENTIFIER(1), INTEGER(1))

    def test_getitem_returns_the_subidentifier_at_the_given_index(self):
        for i, s in enumerate(self.internet):
            self.assertEqual(self.internet[i], s)

    def test_getitem_raises_IndexError_when_the_index_is_out_of_range(self):
        self.assertRaises(
            IndexError,
            self.internet.__getitem__,
            len(self.internet),
        )

    def test_OBJECT_IDENTIFIER_is_hashable(self):
        table = {self.internet: None}
        self.assertIn(self.internet, table)

    def test_iterator_returns_each_subidentifier_in_order(self):
        self.assertEqual(OBJECT_IDENTIFIER(*self.internet), self.internet)

    def test_len_gives_the_number_of_subidentifiers(self):
        self.assertEqual(len(self.internet), 4)

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        self.assertEqual(eval(repr(self.internet)), self.internet)

    def test_str_gives_the_OID_in_dot_separated_format(self):
        self.assertEqual(str(self.internet), "1.3.6.1")

    def test_parse_empty_string_returns_empty_OID(self):
        oid = OBJECT_IDENTIFIER.parse("")
        self.assertEqual(oid, OBJECT_IDENTIFIER())

    def test_parse_single_number_creates_OID_with_just_that_number(self):
        oid = OBJECT_IDENTIFIER.parse("1")
        self.assertEqual(oid, OBJECT_IDENTIFIER(1))

    def test_parse_constructs_OID_from_dot_separated_string(self):
        oid = OBJECT_IDENTIFIER.parse("1.3.6.1")
        self.assertEqual(oid, self.internet)

    def test_parse_ignores_leading_dot(self):
        oid = OBJECT_IDENTIFIER.parse(".1.3.6.1")
        self.assertEqual(oid, self.internet)

    def test_parse_raises_ValueError_on_invalid_input(self):
        self.assertRaises(ValueError, OBJECT_IDENTIFIER.parse, "internet")
        self.assertRaises(ValueError, OBJECT_IDENTIFIER.parse, "1.3.6.1.")

    def test_parse_raises_ValueError_on_invalid_first_subidentifier(self):
        self.assertRaises(ValueError, OBJECT_IDENTIFIER.parse, "3")

    def test_parse_raises_ValueError_on_invalid_second_subidentifier(self):
        self.assertRaises(ValueError, OBJECT_IDENTIFIER.parse, "1.40")

    def test_extend_does_not_modify_the_original_object(self):
        oid = OBJECT_IDENTIFIER(*self.internet)
        _ = oid.extend(2)
        self.assertEqual(oid, self.internet)

    def test_extend_returns_copy_with_subidentifer_appended_to_the_end(self):
        oid = self.internet.extend(2)
        self.assertEqual(len(oid), len(self.internet) + 1)
        self.assertEqual(oid[:len(self.internet)], self.internet[:])
        self.assertEqual(oid[-1], 2)

    def test_extend_handles_many_subidentifers_at_once(self):
        oid = self.internet.extend(2, 1, 1, 1, 0)
        self.assertEqual(oid, OBJECT_IDENTIFIER(1, 3, 6, 1, 2, 1, 1, 1, 0))

    def test_startswith_returns_True_if_prefix_matches(self):
        self.assertTrue(self.internet.startswith(OBJECT_IDENTIFIER(1, 3, 6)))
        self.assertTrue(self.internet.startswith(self.internet))

    def test_startswith_returns_False_if_prefix_does_not_match(self):
        self.assertFalse(self.internet.startswith(OBJECT_IDENTIFIER(1, 3, 5)))

    def test_startswith_returns_False_if_prefix_is_longer(self):
        self.assertFalse(self.internet.startswith(self.internet.extend(0)))

    def test_INTEGER_index_appends_value_to_OID(self):
        i = INTEGER(2)
        oid = self.internet.withIndex(i)
        self.assertEqual(oid, self.internet.extend(i.value))

    def test_IMPLIED_OCTET_STRING_index_has_no_length_byte(self):
        s = OCTET_STRING(b"test string")
        oid = self.internet.withIndex(s, implied=True)
        self.assertEqual(oid, self.internet.extend(*s.data))

    def test_OCTET_STRING_index_includes_length_byte(self):
        s = OCTET_STRING(b"test string")
        oid = self.internet.withIndex(s, implied=False)
        self.assertEqual(oid, self.internet.extend(len(s.data), *s.data))

    def test_NULL_index_has_no_effect(self):
        oid = self.internet.withIndex(NULL())
        self.assertEqual(oid, self.internet)

    def test_IMPLIED_OBJECT_IDENTIFIER_index_has_no_length_byte(self):
        oid = self.internet.withIndex(self.internet, implied=True)
        self.assertEqual(oid, self.internet.extend(*self.internet))

    def test_OBJECT_IDENTIFIER_index_includes_length_byte(self):
        oid = self.internet.withIndex(self.internet, implied=False)

        self.assertEqual(
            oid,
            self.internet.extend(len(self.internet), *self.internet),
        )

    def test_implied_argument_only_applies_to_the_last_object_in_index(self):
        s1 = OCTET_STRING(b"the first test string")
        s2 = OCTET_STRING(b"the second test string")
        oid = self.internet.withIndex(s1, s2, implied=True)

        self.assertEqual(
            oid,
            self.internet.extend(len(s1.data), *s1.data, *s2.data),
        )

    def test_decodeIndex_raises_BadPrefix_when_prefix_is_too_long(self):
        self.assertRaises(
            OBJECT_IDENTIFIER.BadPrefix,
            self.internet.decodeIndex,
            OBJECT_IDENTIFIER(1, 3, 6, 1, 2, 1, 1, 1),
        )

    def test_decodeIndex_raises_BadPrefix_when_prefix_does_not_match(self):
        self.assertRaises(
            OBJECT_IDENTIFIER.BadPrefix,
            self.internet.decodeIndex,
            OBJECT_IDENTIFIER(1, 2, 3),
        )

    def test_decodeIndex_raises_IndexDecodeError_if_there_are_leftovers(self):
        self.assertRaises(
            OBJECT_IDENTIFIER.IndexDecodeError,
            self.internet.extend(0).decodeIndex,
            self.internet,
        )

    def test_decodeIndex_raises_IndexDecodeError_if_OID_is_too_short(self):
        self.assertRaises(
            OBJECT_IDENTIFIER.IndexDecodeError,
            self.internet.decodeIndex,
            self.internet,
            INTEGER,
        )

    def test_decodeIndex_turns_single_subidentifier_into_INTEGER(self):
        i = 3
        oid = self.internet.extend(i)
        index = oid.decodeIndex(self.internet, INTEGER)
        self.assertEqual(index[0], INTEGER(i))

    def test_decodeIndex_infers_length_of_IMPLIED_OCTET_STRING(self):
        data = b"test data"
        oid = self.internet.extend(*data)
        index = oid.decodeIndex(self.internet, OCTET_STRING, implied=True)
        self.assertEqual(index[0], OCTET_STRING(data))

    def test_decodeIndex_reads_length_for_OCTET_STRING(self):
        data = b"test data"
        oid = self.internet.extend(len(data), *data)
        index = oid.decodeIndex(self.internet, OCTET_STRING, implied=False)
        self.assertEqual(index[0], OCTET_STRING(data))

    def test_decodeIndex_reads_nothing_for_NULL(self):
        index = self.internet.decodeIndex(self.internet, NULL)
        self.assertEqual(index[0], NULL())

    def test_decodeIndex_infers_length_of_IMPLIED_OBJECT_IDENTIFIER(self):
        oid = self.internet.extend(*self.internet)
        index = oid.decodeIndex(self.internet, OBJECT_IDENTIFIER, implied=True)
        self.assertEqual(index[0], self.internet)

    def test_decodeIndex_reads_length_for_OBJECT_IDENTIFIER(self):
        oid = self.internet.extend(len(self.internet), *self.internet)
        index = oid.decodeIndex(self.internet, OBJECT_IDENTIFIER, implied=False)
        self.assertEqual(index[0], self.internet)

    def test_decodeIndex_restricts_first_two_subidentifiers(self):
        _ = self.internet.extend(2, 39).decodeIndex(
            self.internet,
            OBJECT_IDENTIFIER,
            implied=True,
        )

        self.assertRaises(
            OBJECT_IDENTIFIER.IndexDecodeError,
            self.internet.extend(3).decodeIndex,
            self.internet,
            OBJECT_IDENTIFIER,
            implied=True,
        )

        self.assertRaises(
            OBJECT_IDENTIFIER.IndexDecodeError,
            self.internet.extend(2, 40).decodeIndex,
            self.internet,
            OBJECT_IDENTIFIER,
            implied=True,
        )

    def test_decodeIndex_implied_only_affects_the_last_argument(self):
        data1 = b"something something"
        data2 = b"something else"
        oid = self.internet.extend(len(data1), *data1, *data2)

        index = oid.decodeIndex(
            self.internet,
            OCTET_STRING,
            OCTET_STRING,
            implied=True,
        )

    def test_null_OID_decodes_to_zero_dot_zero(self):
        oid = OBJECT_IDENTIFIER.decode(b"\x06\x01\x00")
        self.assertEqual(oid, OBJECT_IDENTIFIER(0, 0))

    def test_decode_divides_the_first_byte_by_40(self):
        oid = OBJECT_IDENTIFIER.decode(b"\x06\x01\x2b")
        self.assertEqual(oid, OBJECT_IDENTIFIER(1, 3))

    def test_decode_raises_ParseError_when_the_first_byte_is_invalid(self):
        for i in range(120, 255):
            encoding = b"\x06\x01" + bytes((i,))
            self.assertRaises(ParseError, OBJECT_IDENTIFIER.decode, encoding)

    def test_decode_reads_each_byte_with_msb_unset_as_a_subidentifier(self):
        oid = OBJECT_IDENTIFIER.decode(b"\x06\x03\x2b\x06\x01")
        self.assertEqual(oid, self.internet)

    def test_decode_concatenates_the_lowest_seven_bits_while_msb_is_set(self):
        oid = OBJECT_IDENTIFIER.decode(b"\x06\x04\x2b\xa9\xb4\x5a")
        self.assertEqual(oid, OBJECT_IDENTIFIER(1, 3, 0xa5a5a))

    def test_encode_always_produces_at_least_one_byte(self):
        self.assertEqual(OBJECT_IDENTIFIER().encode(), b"\x06\x01\x00")
        self.assertEqual(OBJECT_IDENTIFIER(2).encode(), b"\x06\x01\x50")
        self.assertEqual(OBJECT_IDENTIFIER(1, 3).encode(), b"\x06\x01\x2b")

    def test_encode_uses_single_byte_for_subidentifiers_under_128(self):
        self.assertEqual(
            OBJECT_IDENTIFIER(*range(128)).encode(),
            b"\x06\x7f\x01" + bytes(range(2, 128)),
        )

    def test_encode_uses_long_form_for_subidentifiers_over_127(self):
        self.assertEqual(
            OBJECT_IDENTIFIER(1, 3, 128, 0x1234).encode(),
            b"\x06\x05\x2b\x81\x00\xa4\x34",
        )

        self.assertEqual(
            OBJECT_IDENTIFIER(1, 3, 0xffffffffffffff).encode(),
            b"\x06\x09\x2b\xff\xff\xff\xff\xff\xff\xff\x7f",
        )

class SEQUENCETest(unittest.TestCase):
    def test_tag_universal_constructed_16(self):
        self.assertEqual(SEQUENCE.TAG.cls, Tag.Class.UNIVERSAL)
        self.assertEqual(SEQUENCE.TAG.constructed, True)
        self.assertEqual(SEQUENCE.TAG.number, 16)

if __name__ == '__main__':
    unittest.main()
