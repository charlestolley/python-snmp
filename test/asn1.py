__all__ = ["INTEGERTest", "OCTET_STRINGTest", "NULLTest"]

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

if __name__ == '__main__':
    unittest.main()
