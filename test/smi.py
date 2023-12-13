__all__ = [
    "BoundedIntegerTest", "IntegerTypesTest",
    "IpAddressTest", "OpaqueTest",
    "ZeroDotZeroTest",
]

import unittest
from snmp.ber import *
from snmp.smi import BoundedInteger
from snmp.smi import *
from snmp.types import *
from snmp.utils import NumberGenerator

from snmp.asn1 import *

class BoundedIntegerTest(unittest.TestCase):
    class Nybble(BoundedInteger):
        BITS = 4
        SIGNED = True
        TAG = Tag(2, cls = Tag.Class.PRIVATE)

    class UnsignedNybble(BoundedInteger):
        BITS = 4
        SIGNED = False
        TAG = Tag(1, cls = Tag.Class.PRIVATE)

    def test_two_instances_of_incompatible_subtypes_are_not_equal(self):
        n = self.Nybble(0)
        u = self.UnsignedNybble(0)
        self.assertNotEqual(n, u)

    def test_constructor_raises_ValueError_if_signed_value_out_of_range(self):
        self.assertRaises(ValueError, self.Nybble, 8)
        self.assertRaises(ValueError, self.Nybble, -9)

    def test_constructor_succeeds_if_signed_value_is_in_range(self):
        n = self.Nybble(7)
        n = self.Nybble(-8)

    def test_constructor_raises_ValueError_unsigned_value_out_of_range(self):
        self.assertRaises(ValueError, self.UnsignedNybble, 16)
        self.assertRaises(ValueError, self.UnsignedNybble, -1)

    def test_constructor_succeeds_if_unsigned_value_is_in_range(self):
        n = self.UnsignedNybble(15)
        n = self.UnsignedNybble(0)

    def test_decode_raises_ParseError_if_signed_value_is_out_of_range(self):
        self.assertRaises(ParseError, self.Nybble.decode, b"\xc2\x01\x08")
        self.assertRaises(ParseError, self.Nybble.decode, b"\xc2\x01\xf7")

    def test_decode_succeeds_if_signed_value_is_in_range(self):
        n = self.Nybble.decode(b"\xc2\x01\x07")
        n = self.Nybble.decode(b"\xc2\x01\xf8")

    def test_decode_raises_ParseError_if_unsigned_is_value_out_of_range(self):
        encodings = [
            b"\xc1\x01\x10",
            b"\xc1\x01\xff",
        ]

        for e in encodings:
            self.assertRaises(ParseError, self.UnsignedNybble.decode, e)

    def test_decode_succeeds_if_unsigned_value_is_in_range(self):
        encodings = [
            b"\xc1\x01\x0f",
            b"\xc1\x01\x00",
        ]

        for encoding in encodings:
            u = self.UnsignedNybble.decode(encoding)

class IntegerTypesTest(unittest.TestCase):
    def help_test_integer_boundaries_and_tag(self, cls, a, b, c, d):
        # Lower bound
        self.assertRaisesRegex(ParseError, "[Rr]ange", cls.decode, a)
        _ = cls.decode(b)

        # Upper bound
        _ = cls.decode(c)
        self.assertRaisesRegex(ParseError, "[Rr]ange", cls.decode, d)

    def test_Integer32_equals_INTEGER_with_the_same_value(self):
        value = 4
        self.assertEqual(Integer32(value), INTEGER(value))

    def test_Unsigned32_equals_Gauge32_with_the_same_value(self):
        value = 9
        self.assertEqual(Unsigned32(value), Gauge32(value))

    def test_Integer32_does_not_equal_Unsigned32_with_the_same_value(self):
        value = 45
        self.assertNotEqual(Integer32(value), Unsigned32(value))

    def test_Integer32_does_not_equal_int_with_the_same_value(self):
        value = 116
        self.assertNotEqual(Integer32(value), value)

    def test_Integer32_has_the_expected_range_and_tag(self):
        self.help_test_integer_boundaries_and_tag(
            Integer32,
            b"\x02\x05\xff\x7f\xff\xff\xff",
            b"\x02\x04\x80\x00\x00\x00",
            b"\x02\x04\xff\xff\xff\xff",
            b"\x02\x05\x00\x80\x00\x00\x00",
        )

    def test_Unsigned32_has_the_expected_range_and_tag(self):
        self.help_test_integer_boundaries_and_tag(
            Unsigned32,
            b"\x42\x01\xff",
            b"\x42\x01\x00",
            b"\x42\x05\x00\xff\xff\xff\xff",
            b"\x42\x05\x01\x00\x00\x00\x00",
        )

    def test_Counter32_has_the_expected_range_and_tag(self):
        self.help_test_integer_boundaries_and_tag(
            Counter32,
            b"\x41\x01\xff",
            b"\x41\x01\x00",
            b"\x41\x05\x00\xff\xff\xff\xff",
            b"\x41\x05\x01\x00\x00\x00\x00",
        )

    def test_Gauge32_has_the_expected_range_and_tag(self):
        self.help_test_integer_boundaries_and_tag(
            Gauge32,
            b"\x42\x01\xff",
            b"\x42\x01\x00",
            b"\x42\x05\x00\xff\xff\xff\xff",
            b"\x42\x05\x01\x00\x00\x00\x00",
        )

    def test_TimeTicks_has_the_expected_range_and_tag(self):
        self.help_test_integer_boundaries_and_tag(
            TimeTicks,
            b"\x43\x01\xff",
            b"\x43\x01\x00",
            b"\x43\x05\x00\xff\xff\xff\xff",
            b"\x43\x05\x01\x00\x00\x00\x00",
        )

    def test_Counter64_has_the_expected_range_and_tag(self):
        self.help_test_integer_boundaries_and_tag(
            Counter64,
            b"\x46\x01\xff",
            b"\x46\x01\x00",
            b"\x46\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff",
            b"\x46\x09\x01\x00\x00\x00\x00\x00\x00\x00\x00",
        )

    def test_eval_repr_Integer32_is_the_same_type(self):
        self.assertIsInstance(eval(repr(Integer32(0))), Integer32)

    def test_eval_repr_Unsigned32_is_the_same_type(self):
        self.assertIsInstance(eval(repr(Unsigned32(0))), Unsigned32)

    def test_eval_repr_Counter32_is_the_same_type(self):
        self.assertIsInstance(eval(repr(Counter32(0))), Counter32)

    def test_eval_repr_Gauge32_is_the_same_type(self):
        self.assertIsInstance(eval(repr(Gauge32(0))), Gauge32)

    def test_eval_repr_TimeTicks_is_the_same_type(self):
        self.assertIsInstance(eval(repr(TimeTicks(0))), TimeTicks)

    def test_eval_repr_Counter64_is_the_same_type(self):
        self.assertIsInstance(eval(repr(Counter64(0))), Counter64)

class IpAddressTest(unittest.TestCase):
    def setUp(self):
        self.addr = "12.34.56.78"
        self.encoding = b"\x0c\x22\x38\x4e"
        self.data = b"\x40\x04" + self.encoding

    def testRepr(self):
        addr = IpAddress(self.addr)
        self.assertEqual(eval(repr(addr)), addr)

    def testEquals(self):
        self.assertTrue(IpAddress(self.addr).equals(OctetString(self.encoding)))

    def testNotEquals(self):
        self.assertFalse(IpAddress(self.addr).equals(OctetString(self.data)))

    def testDecode(self):
        self.assertEqual(IpAddress.decode(self.data), IpAddress(self.addr))

    def testDecodeTooShort(self):
        self.assertRaises(ParseError, IpAddress.decode, b"\x40\x03abc")

    def testDecodeTooLong(self):
        self.assertRaises(ParseError, IpAddress.decode, b"\x40\x05badIP")

    def testEncode(self):
        self.assertEqual(IpAddress(self.addr).encode(), self.data)

class OpaqueTest(unittest.TestCase):
    def setUp(self):
        self.data = b"this could contain anyting"

    def testEquality(self):
        self.assertTrue(Opaque(self.data).equals(OctetString(self.data)))

    def testRepr(self):
        self.assertEqual(eval(repr(Opaque(self.data))), Opaque(self.data))

class ZeroDotZeroTest(unittest.TestCase):
    def setUp(self):
        self.data = b"\x06\x01\x00"

    def testDecode(self):
        self.assertEqual(zeroDotZero, OID.decode(self.data))

    def testEncode(self):
        self.assertEqual(zeroDotZero.encode(), self.data)

if __name__ == '__main__':
    unittest.main()
