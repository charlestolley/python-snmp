__all__ = [
    "BoundedIntegerTest", "IntegerTypesTest",
    "OctetStringTest", "IpAddressTest", "OpaqueTest",
    "NoSuchObjectTest", "NoSuchInstanceTest", "EndOfMibViewTest",
    "OIDTest", "ZeroDotZeroTest",
    "VarBindTest", "VarBindListTest",
]

import unittest

from snmp.exception import *
from snmp.asn1 import *
from snmp.ber import *
from snmp.smi import BoundedInteger
from snmp.smi import *
from snmp.utils import *

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
        self.assertRaises(ParseError, self.Nybble.decodeExact, b"\xc2\x01\x08")
        self.assertRaises(ParseError, self.Nybble.decodeExact, b"\xc2\x01\xf7")

    def test_decode_succeeds_if_signed_value_is_in_range(self):
        n = self.Nybble.decodeExact(b"\xc2\x01\x07")
        n = self.Nybble.decodeExact(b"\xc2\x01\xf8")

    def test_decode_raises_ParseError_if_unsigned_is_value_out_of_range(self):
        encodings = [
            b"\xc1\x01\x10",
            b"\xc1\x01\xff",
        ]

        for e in encodings:
            self.assertRaises(ParseError, self.UnsignedNybble.decodeExact, e)

    def test_decode_succeeds_if_unsigned_value_is_in_range(self):
        encodings = [
            b"\xc1\x01\x0f",
            b"\xc1\x01\x00",
        ]

        for encoding in encodings:
            u = self.UnsignedNybble.decodeExact(encoding)

    def test_decodeIndex_raises_IndexDecodeError_if_out_of_range(self):
        self.assertRaises(
            OBJECT_IDENTIFIER.IndexDecodeError,
            OBJECT_IDENTIFIER(1, 3, 6, 1, 8).decodeIndex,
            OBJECT_IDENTIFIER(1, 3, 6, 1),
            self.Nybble,
        )

class IntegerTypesTest(unittest.TestCase):
    def help_test_integer_boundaries_and_tag(self, cls, a, b, c, d):
        # Lower bound
        self.assertRaisesRegex(ParseError, "[Rr]ange", cls.decodeExact, a)
        _ = cls.decodeExact(b)

        # Upper bound
        _ = cls.decodeExact(c)
        self.assertRaisesRegex(ParseError, "[Rr]ange", cls.decodeExact, d)

    def help_test_unsigned_boundaries_and_tag(self, cls, a, b, c):
        # Zero
        _ = cls.decodeExact(a)

        # Upper bound
        _ = cls.decodeExact(b)
        self.assertRaisesRegex(ParseError, "[Rr]ange", cls.decodeExact, c)

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
        self.help_test_unsigned_boundaries_and_tag(
            Unsigned32,
            b"\x42\x01\x00",
            b"\x42\x05\x00\xff\xff\xff\xff",
            b"\x42\x05\x01\x00\x00\x00\x00",
        )

    def test_Counter32_has_the_expected_range_and_tag(self):
        self.help_test_unsigned_boundaries_and_tag(
            Counter32,
            b"\x41\x01\x00",
            b"\x41\x05\x00\xff\xff\xff\xff",
            b"\x41\x05\x01\x00\x00\x00\x00",
        )

    def test_Gauge32_has_the_expected_range_and_tag(self):
        self.help_test_unsigned_boundaries_and_tag(
            Gauge32,
            b"\x42\x01\x00",
            b"\x42\x05\x00\xff\xff\xff\xff",
            b"\x42\x05\x01\x00\x00\x00\x00",
        )

    def test_TimeTicks_has_the_expected_range_and_tag(self):
        self.help_test_unsigned_boundaries_and_tag(
            TimeTicks,
            b"\x43\x01\x00",
            b"\x43\x05\x00\xff\xff\xff\xff",
            b"\x43\x05\x01\x00\x00\x00\x00",
        )

    def test_Counter64_has_the_expected_range_and_tag(self):
        self.help_test_unsigned_boundaries_and_tag(
            Counter64,
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

class OctetStringTest(unittest.TestCase):
    def test_constructor_uses_empty_data_by_default(self):
        self.assertEqual(OctetString().data, b"")

    def test_constructor_raises_ValueError_if_over_65535_bytes_long(self):
        self.assertRaises(ValueError, OctetString, bytes(65536))

    def test_decode_raises_ParseError_if_over_65535_bytes_long(self):
        encoding = encode(OctetString.TAG, bytes(65536))
        self.assertRaises(ParseError, OctetString.decodeExact, encoding)

    def test_OctetString_does_not_equal_IpAddress(self):
        data = b"\xc0\x22\x38\x4e"
        self.assertNotEqual(OctetString(data), IpAddress.construct(data))

    def test_original_gives_subbytes_of_the_full_encoding_if_copy_False(self):
        encoding = b"\x04\x00"
        s = OctetString.decodeExact(encoding, copy=False)
        self.assertIsInstance(s.original, subbytes)
        self.assertEqual(s.original.data, encoding)

    def test_the_result_of_eval_repr_has_identical_original_data(self):
        raw = b"the quick brown fox jumps over the lazy dog"
        data = subbytes(raw, 4, 25)
        s = OctetString(data)
        copy = eval(repr(s))
        self.assertEqual(repr(s.original), repr(copy.original))

    def test_decodeIndex_raises_IndexDecodeError_if_check_fails(self):
        class MiniOctetString(OctetString):
            @classmethod
            def check(cls, data):
                if len(data) > 4:
                    raise ValueError("That string is too big")

        self.assertRaises(
            OBJECT_IDENTIFIER.IndexDecodeError,
            OBJECT_IDENTIFIER(1, 3, 6, 1, 99, 104, 117, 99, 107).decodeIndex,
            OBJECT_IDENTIFIER(1, 3, 6, 1),
            MiniOctetString,
            implied=True,
        )

class IpAddressTest(unittest.TestCase):
    def setUp(self):
        self.addr = "12.34.56.78"
        self.data = b"\x0c\x22\x38\x4e"
        self.encoding = b"\x40\x04" + self.data

    def test_two_objects_with_the_same_address_are_equal(self):
        self.assertEqual(IpAddress("1.2.3.4"), IpAddress("1.2.3.4"))

    def test_two_objects_with_different_addresses_are_not_equal(self):
        self.assertNotEqual(IpAddress("1.2.3.4"), IpAddress("4.3.2.1"))

    def test_IpAddress_does_not_equal_OctetString(self):
        data = b"\xc0\x22\x38\x4e"
        self.assertNotEqual(IpAddress.construct(data), OctetString(data))

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        addr = IpAddress(self.addr)
        self.assertEqual(eval(repr(addr)), addr)

    def test_constructor_raises_ValueError_if_addr_is_not_IPv4_address(self):
        self.assertRaises(ValueError, IpAddress, "asdf")
        self.assertRaises(ValueError, IpAddress, "1.2.3.")
        self.assertRaises(ValueError, IpAddress, "::1")

    def test_index_does_not_include_length_byte(self):
        oid = OBJECT_IDENTIFIER(1, 3, 6, 1)
        addr = IpAddress(self.addr)
        self.assertEqual(oid.withIndex(addr), oid.extend(*self.data))

    def test_decode_raises_ParseError_if_data_is_not_four_bytes(self):
        encodings = [
            b"\x40\x03\xab\xcd\xef",
            b"\x40\x05\x12\x34\x56\x78\x90",
        ]

        for encoding in encodings:
            self.assertRaises(ParseError, IpAddress.decodeExact, encoding)

    def test_data_returns_network_bytes(self):
        self.assertEqual(IpAddress(self.addr).data, self.data)
        self.assertEqual(IpAddress.decodeExact(self.encoding).data, self.data)

    def test_encode_uses_data_for_the_payload(self):
        self.assertEqual(IpAddress(self.addr).encode(), self.encoding)

    def test_decodeIndex_raises_IndexDecodeError_if_the_encoding_is_too_long(self):
        internet = OBJECT_IDENTIFIER(1,3,6,1)
        oid = internet.extend(4, 192, 168, 0, 1)

        self.assertRaises(
            OBJECT_IDENTIFIER.IndexDecodeError,
            oid.decodeIndex,
            internet,
            IpAddress,
        )

    def test_decodeIndex_implied_argument_is_ignored(self):
        internet = OBJECT_IDENTIFIER(1,3,6,1)
        oid = internet.extend(192, 168, 0, 1)

        addr = IpAddress("192.168.0.1")
        a = oid.decodeIndex(internet, IpAddress, implied=False)[0]
        self.assertEqual(addr, a)

        b = oid.decodeIndex(internet, IpAddress, implied=True)[0]
        self.assertEqual(a, b)

    def test_decodeIndex_address_does_not_have_to_be_the_last_field(self):
        internet = OBJECT_IDENTIFIER(1,3,6,1)
        oid = internet.extend(192, 168, 0, 1).extend(8080)

        addr, port = oid.decodeIndex(internet, IpAddress, Integer)
        self.assertEqual(addr, IpAddress("192.168.0.1"))
        self.assertEqual(port.value, 8080)

class OpaqueTest(unittest.TestCase):
    def test_result_of_eval_repr_is_equal_to_the_original(self):
        o = Opaque(b"this could contain anything")
        self.assertEqual(eval(repr(o)), o)

class NoSuchObjectTest(unittest.TestCase):
    def test_tag_context_specific_primitive_0(self):
        self.assertEqual(NoSuchObject.TAG.cls, Tag.Class.CONTEXT_SPECIFIC)
        self.assertEqual(NoSuchObject.TAG.constructed, False)
        self.assertEqual(NoSuchObject.TAG.number, 0)

    def test_decodes_empty_payload(self):
        _ = NoSuchObject.decodeExact(b"\x80\x00")

    def test_NoSuchObject_does_not_equal_NULL(self):
        self.assertNotEqual(NoSuchObject(), NULL())

class NoSuchInstanceTest(unittest.TestCase):
    def test_tag_context_specific_primitive_1(self):
        self.assertEqual(NoSuchInstance.TAG.cls, Tag.Class.CONTEXT_SPECIFIC)
        self.assertEqual(NoSuchInstance.TAG.constructed, False)
        self.assertEqual(NoSuchInstance.TAG.number, 1)

    def test_decodes_empty_payload(self):
        _ = NoSuchInstance.decodeExact(b"\x81\x00")

    def test_does_not_equal_NULL(self):
        self.assertNotEqual(NoSuchInstance(), NULL())

class EndOfMibViewTest(unittest.TestCase):
    def test_tag_context_specific_primitive_2(self):
        self.assertEqual(EndOfMibView.TAG.cls, Tag.Class.CONTEXT_SPECIFIC)
        self.assertEqual(EndOfMibView.TAG.constructed, False)
        self.assertEqual(EndOfMibView.TAG.number, 2)

    def test_decodes_empty_payload(self):
        _ = EndOfMibView.decodeExact(b"\x82\x00")

    def test_does_not_equal_NULL(self):
        self.assertNotEqual(EndOfMibView(), NULL())

from snmp.ber import decode_length
class OIDTest(unittest.TestCase):
    def setUp(self):
        self.internet = OID(1, 3, 6, 1)

    def test_constructor_accepts_up_to_128_subidentifiers(self):
        _ = OID(*range(128))

    def test_constructor_raises_ValueError_with_over_128_subidentifiers(self):
        self.assertRaises(ValueError, OID, *range(129))

    def test_decode_accepts_up_to_128_subidentifiers(self):
        encoding = b"\x06\x7f\x2b" + bytes(range(126))
        _ = OID.decodeExact(encoding)

    def test_decode_raises_ParseError_with_over_128_subidentifiers(self):
        encoding = b"\x06\x81\x80\x2b" + bytes(range(127))
        self.assertRaises(ParseError, OID.decodeExact, encoding)

    def test_constructor_accepts_32_bit_unsigned_subidentifiers(self):
        oid = OID(1, 3, (1 << 32) - 1)

    def test_constructor_raises_ValueError_for_33_bit_subidentifiers(self):
        self.assertRaises(ValueError, OID, 1, 3, 1 << 32)

    def test_decode_accepts_32_bit_unsigned_subidentifiers(self):
        encoding = b"\x06\x06\x2b\x8f\xff\xff\xff\x7f"
        oid = OID.decodeExact(encoding)
        self.assertEqual(oid[2], (1 << 32) - 1)

    def test_decode_raises_ParseError_for_33_bit_subidentifiers(self):
        encoding = b"\x06\x06\x2b\x90\x80\x80\x80\x00"
        self.assertRaises(ParseError, OID.decodeExact, encoding)

    def test_getIndex_uses_Integer_by_default(self):
        oid = self.internet.extend(4)
        index = oid.getIndex(self.internet)
        self.assertIsInstance(index, Integer)
        self.assertEqual(index.value, 4)

    def test_getIndex_works_with_non_integer_types(self):
        data = b"OCTET STRING"
        oid = self.internet.extend(len(data), *data)
        index = oid.getIndex(self.internet, OctetString)
        self.assertEqual(index.data, data)

    def test_getIndex_uses_the_implied_argument(self):
        data = b"OCTET STRING"
        oid = self.internet.extend(*data)
        index = oid.getIndex(self.internet, OctetString, implied=True)
        self.assertEqual(index.data, data)

class ZeroDotZeroTest(unittest.TestCase):
    def test_contains_two_zeros(self):
        self.assertEqual(len(zeroDotZero), 2)
        for subidentifier in zeroDotZero:
            self.assertEqual(subidentifier, 0)

class VarBindTest(unittest.TestCase):
    def setUp(self):
        self.oid = OID(1, 3, 6, 1, 2, 1, 1, 1, 0)

    def test_length_is_always_2(self):
        varbind = VarBind(OID(), OctetString())
        self.assertEqual(len(varbind), 2)

    def test_iter_returns_name_then_value(self):
        name = OID(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)
        value = OctetString(b"Interface 1")
        varbind = VarBind(name, value)

        i = iter(varbind)
        self.assertEqual(next(i), name)
        self.assertEqual(next(i), value)
        self.assertRaises(StopIteration, next, i)

    def test_two_VarBinds_with_the_same_name_and_value_are_equal(self):
        self.assertEqual(
            VarBind(self.oid, OctetString(b"a string of bytes")),
            VarBind(self.oid, OctetString(b"a string of bytes")),
        )

    def test_two_VarBinds_with_different_name_are_not_equal(self):
        self.assertNotEqual(
            VarBind(OID(1, 2, 3, 4, 5, 6, 7, 8, 9), Null()),
            VarBind(OID(1, 3, 6, 1, 2, 1, 1, 1, 0), Null()),
        )

    def test_two_VarBinds_with_different_values_are_not_equal(self):
        self.assertNotEqual(
            VarBind(self.oid, Integer(15)),
            VarBind(self.oid, Integer(149)),
        )

    def test_two_VarBinds_with_different_value_types_are_not_equal(self):
        self.assertNotEqual(
            VarBind(self.oid, Null()),
            VarBind(self.oid, NoSuchInstance()),
        )

    def test_constructor_parses_name_as_OID(self):
        varbind = VarBind(str(self.oid))
        self.assertEqual(varbind.name, self.oid)

    def test_value_is_NULL_by_default(self):
        varbind = VarBind(self.oid)
        self.assertEqual(varbind.value, Null())

    def test_str_formats_OID_colon_value(self):
        varbind = VarBind("1.3.6.1.2.1.1.1.0", OctetString(b"description"))
        s = "1.3.6.1.2.1.1.1.0: OctetString(b'description')"
        self.assertEqual(str(varbind), s)

    def test_the_result_of_eval_repr_equals_the_original_object(self):
        varbind = VarBind(self.oid, Integer(0))
        self.assertEqual(eval(repr(varbind)), varbind)

    def helpAssertParseError(self, hex_string, **kwargs):
        encoding = bytes.fromhex(hex_string)

        try:
            VarBind.decodeExact(encoding)
        except ParseError as err:
            data = subbytes(encoding, **kwargs)
            self.assertEqual(err.data, data)
        else:
            raise AssertionError("ParseError not raised by decodeExact")

    def test_decode_raises_ParseError_on_missing_fields(self):
        self.helpAssertParseError("30 00", start=2)
        self.helpAssertParseError("30 03 06 01 00", start=5)

    def test_decode_raises_ParseError_on_extra_fields(self):
        self.helpAssertParseError("30 07 06 01 00 04 00 04 00", start=7)

    def test_decode_raises_ParseError_if_name_is_not_an_OID(self):
        self.helpAssertParseError("30 03 02 01 00", start=2)

    def test_decode_raises_ParseError_on_unknown_tag(self):
        self.helpAssertParseError("30 06 06 01 00 01 01 00", start=5)

    def test_decode_recognized_any_smi_type_or_special_NULL_type(self):
        encodings = (
            ("30 06 06 01 00 02 01 00", Integer(0)),
            ("30 05 06 01 00 04 00", OctetString()),
            ("30 05 06 01 00 05 00", Null()),
            ("30 06 06 01 00 06 01 00", zeroDotZero),
            ("30 09 06 01 00 40 04 01 02 03 04", IpAddress("1.2.3.4")),
            ("30 06 06 01 00 41 01 00", Counter32(0)),
            ("30 06 06 01 00 42 01 00", Gauge32(0)),
            ("30 06 06 01 00 43 01 00", TimeTicks(0)),
            ("30 05 06 01 00 44 00", Opaque()),
            ("30 06 06 01 00 46 01 00", Counter64(0)),
            ("30 05 06 01 00 80 00", NoSuchObject()),
            ("30 05 06 01 00 81 00", NoSuchInstance()),
            ("30 05 06 01 00 82 00", EndOfMibView()),
        )

        for hexstr, value in encodings:
            encoding = bytes.fromhex(hexstr)
            varbind = VarBind.decodeExact(encoding)
            self.assertEqual(varbind.value, value)

    def test_generated_encoding_is_decodable(self):
        varbinds = (
            VarBind("1.3.6.1"),
            VarBind("1.3.6.1.2.1.1.1.0", OctetString(b"System Description")),
            VarBind("1.3.6.1.2.1.2.2.1.2.1", OctetString(b"Interface 1")),
            VarBind("1.3.6.1.2.1.2.2.1.4.1", Integer(1500)),
        )

        for varbind in varbinds:
            encoding = varbind.encode()
            self.assertEqual(VarBind.decodeExact(encoding), varbind)

class VarBindListTest(unittest.TestCase):
    def setUp(self):
        ifEntry = OID(1, 3, 6, 1, 2, 1, 2, 2, 1)
        self.ifIndex = Integer(1)

        self.ifDescr         = ifEntry.extend(2)
        self.ifMtu           = ifEntry.extend(4)
        self.ifPhysAddress   = ifEntry.extend(6)
        self.ifSpecific      = ifEntry.extend(22)

        self.varbinds = (
            VarBind(self.ifDescr.withIndex(self.ifIndex), OctetString(b"lo")),
            VarBind(self.ifMtu.withIndex(self.ifIndex), Integer(1500)),
            VarBind(
                self.ifPhysAddress.withIndex(self.ifIndex),
                OctetString(b"macadr"),
            ),
            VarBind(self.ifSpecific.withIndex(self.ifIndex), zeroDotZero),
        )

    def test_bool_evaluates_to_False_when_the_list_is_empty(self):
        vblist = VarBindList()
        self.assertFalse(vblist)

    def test_bool_evaluates_to_True_when_the_list_is_not_empty(self):
        vblist = VarBindList(*self.varbinds)
        self.assertTrue(vblist)

    def test_length_matches_the_number_of_VarBinds(self):
        vblist = VarBindList(*self.varbinds)
        self.assertEqual(len(vblist), len(self.varbinds))

    def test_iter_returns_varbinds_in_the_same_order_they_were_give(self):
        vblist = VarBindList(*self.varbinds)
        for a, b in zip(self.varbinds, vblist):
            self.assertEqual(a, b)

    def test_getitem_returns_the_ith_varbind(self):
        vblist = VarBindList(*self.varbinds)
        for i, varbind in enumerate(self.varbinds):
            self.assertEqual(vblist[i], varbind)

    def test_getitem_slice_returns_tuple_of_VarBind(self):
        vblist = VarBindList(*self.varbinds)
        self.assertEqual(vblist[1:3], self.varbinds[1:3])

    def test_getitem_raises_IndexError_when_index_is_out_of_range(self):
        vblist = VarBindList(*self.varbinds)
        self.assertRaises(IndexError, vblist.__getitem__, len(vblist))

    def test_constructor_turns_OID_string_to_VarBind_with_NULL_value(self):
        oids = (
            self.ifDescr,
            self.ifMtu,
            self.ifPhysAddress,
        )

        vblist = VarBindList(*(str(oid) for oid in oids))
        for i, vb in enumerate(vblist):
            self.assertEqual(vb.name, oids[i])
            self.assertEqual(vb.value, Null())

    def test_constructor_turns_OID_to_VarBind_with_NULL_value(self):
        oids = (
            self.ifDescr,
            self.ifMtu,
            self.ifPhysAddress,
        )

        vblist = VarBindList(*oids)
        for i, vb in enumerate(vblist):
            self.assertEqual(vb.name, oids[i])
            self.assertEqual(vb.value, Null())

    def test_two_VarBindLists_with_identical_entries_are_equal(self):
        self.assertEqual(
            VarBindList(self.ifDescr, self.ifMtu),
            VarBindList(self.ifDescr, self.ifMtu),
        )

    def test_two_VarBindLists_with_different_entries_are_not_equal(self):
        self.assertNotEqual(
            VarBindList(self.ifDescr, self.ifMtu),
            VarBindList(self.ifPhysAddress, self.ifSpecific),
        )

    def test_the_result_of_eval_repr_equals_the_original_object(self):
        vblist = VarBindList(*self.varbinds)
        self.assertEqual(eval(repr(vblist)), vblist)

    def test_the_result_of_decode_encode_equals_the_original_object(self):
        vblist = VarBindList(*self.varbinds)
        self.assertEqual(VarBindList.decodeExact(vblist.encode()), vblist)

if __name__ == '__main__':
    unittest.main()
