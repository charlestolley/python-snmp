__all__ = ["INTEGERTest", "OCTET_STRINGTest"]

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
        self.encoding = b"\x04\x07" + self.payload + b"leftovers"

    def test_tag_universal_primitive_4(self):
        self.assertEqual(OCTET_STRING.TAG.cls, Tag.Class.UNIVERSAL)
        self.assertEqual(OCTET_STRING.TAG.constructed, False)
        self.assertEqual(OCTET_STRING.TAG.number, 4)

    def test_data_returns_the_contents_of_the_string(self):
        for copy in (True, False):
            s, _ = OCTET_STRING.decode(self.encoding, True, copy)
            self.assertEqual(s.data, self.payload)

    def test_wholeMsg_returns_the_full_encoding_if_decoded_as_copy_False(self):
        s, _ = OCTET_STRING.decode(self.encoding, leftovers=True, copy=False)
        self.assertEqual(s.wholeMsg, self.encoding)

if __name__ == '__main__':
    unittest.main()
