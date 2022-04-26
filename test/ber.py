import unittest
from snmp.ber import *
from snmp.ber import decode_length, encode_identifier, encode_length
from snmp.utils import subbytes

class DecodeIdentiferTest(unittest.TestCase):
    def testEmpty(self):
        data = subbytes(b"")
        self.assertRaises(ParseError, decode_identifier, data)

    def testUniversalPrimitive(self):
        data = subbytes(bytes([0x02]))
        self.assertEqual(
            Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 2),
            decode_identifier(data)
        )

    def testUniversalConstructed(self):
        data = subbytes(bytes([0x30]))
        self.assertEqual(
            Identifier(CLASS_UNIVERSAL, STRUCTURE_CONSTRUCTED, 16),
            decode_identifier(data)
        )

    def testApplicationPrimitive(self):
        data = subbytes(bytes([0x41]))
        self.assertEqual(
            Identifier(CLASS_APPLICATION, STRUCTURE_PRIMITIVE, 1),
            decode_identifier(data)
        )

    def testApplicationConstructed(self):
        data = subbytes(bytes([0xa2]))
        self.assertEqual(
            Identifier(CLASS_CONTEXT_SPECIFIC, STRUCTURE_CONSTRUCTED, 2),
            decode_identifier(data)
        )

    def testBigTag(self):
        data = subbytes(bytes([0x1f, 0x2a]))
        self.assertEqual(
            Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 42),
            decode_identifier(data)
        )

    def testHugeTag(self):
        data = subbytes(bytes([0xff, 0x88, 0xdc, 0xfb, 0x76]))
        self.assertEqual(
            Identifier(CLASS_PRIVATE, STRUCTURE_CONSTRUCTED, 0x1173df6),
            decode_identifier(data)
        )

    def testUnexpectedEnd(self):
        data = subbytes(bytes([0x1f, 0x80]))
        self.assertRaises(ParseError, decode_identifier, data)

class DecodeLengthTest(unittest.TestCase):
    def testNoLength(self):
        data = subbytes(b"")
        self.assertRaises(ParseError, decode_length, data)

    def testZeroLength(self):
        length = 0
        data = subbytes(bytes([length]))
        self.assertEqual(length, decode_length(data))

    def testNonZeroLength(self):
        length = 12
        data = subbytes(bytes([length]))
        self.assertEqual(length, decode_length(data))

    def testBigLength(self):
        length = 0x80
        data = subbytes(bytes([0x81, length]))
        self.assertEqual(length, decode_length(data))

    def testHugeLength(self):
        data = subbytes(bytes([0x82, 0x01, 0x8a]))
        self.assertEqual(394, decode_length(data))

    def testInvalidLength(self):
        data = subbytes(bytes([0x82, 0x09]))
        self.assertRaises(ParseError, decode_length, data)

class DecodeTest(unittest.TestCase):
    def testEmptyString(self):
        self.assertRaises(ParseError, decode, b"")

    def testZeroLengthObject(self):
        expected = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 5)
        contents = decode(b"\x05\x00", expected=expected)
        self.assertEqual(b"", contents)

    def testTooShort(self):
        data = b"\x04\x10deadbeef"
        self.assertRaises(ParseError, decode, data)

    def testTooLong(self):
        data = b"\x04\x04deadbeef"
        self.assertRaises(ParseError, decode, data)

    def testLeftovers(self):
        data = b"\x04\x04deadbeef"
        expected = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 4)
        contents, leftovers = decode(data, expected=expected, leftovers=True)
        self.assertEqual(contents, b"dead")
        self.assertEqual(leftovers, b"beef")

    def testWrongType(self):
        data = b"\x02\x08deadbeef"
        expected = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 4)
        self.assertRaises(ParseError, decode, data, expected=expected)

    def testReturnFormat(self):
        data = b"\x04\x08deadbeef"
        identifier, contents, leftovers = decode(data, leftovers=True)
        self.assertTrue(isinstance(identifier, Identifier))
        self.assertEqual(contents, b"deadbeef")
        self.assertTrue(isinstance(leftovers, subbytes))

    def testDecode(self):
        data = b"\x04\x08deadbeef"
        expected = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 4)
        self.assertEqual(b"deadbeef", decode(data, expected=expected))

    def testNoCopy(self):
        data = b"\x04\x08deadbeef"
        expected = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 4)
        contents = decode(data, expected=expected, copy=False)
        self.assertTrue(isinstance(contents, subbytes))
        # NOTE: tightly coupled to the internal implementation of subbytes
        self.assertIs(contents.data, data)

class EncodeIdentifierTest(unittest.TestCase):
    def testUniversalPrimitive(self):
        identifier = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 4)
        self.assertEqual(b"\x04", encode_identifier(identifier))

    def testPrivateConstructed(self):
        identifier = Identifier(CLASS_PRIVATE, STRUCTURE_CONSTRUCTED, 0)
        self.assertEqual(b"\xe0", encode_identifier(identifier))

    def testEncodeLargeTag(self):
        identifier = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 9001)
        self.assertEqual(b"\x1f\xc6\x29", encode_identifier(identifier))

class EncodeLengthTest(unittest.TestCase):
    def testSimpleCase(self):
        self.assertEqual(b"\x10", encode_length(16))

    def testMegabyte(self):
        self.assertEqual(b"\x83\x0f\x42\x40", encode_length(1000 * 1000))

class EncodeTest(unittest.TestCase):
    def testInteger(self):
        identifier = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 2)
        data = int(8888).to_bytes(2, "big")
        self.assertEqual(b"\x02\x02\x22\xb8", encode(identifier, data))

    def testOctetString(self):
        identifier = Identifier(CLASS_UNIVERSAL, STRUCTURE_PRIMITIVE, 4)
        self.assertEqual(b"\x04\x08deadbeef", encode(identifier, b"deadbeef"))

if __name__ == '__main__':
    unittest.main()
