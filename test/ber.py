__all__ = [
    "BigDecodeTest", "DecodeTypesTest", "EncodeTest",
    "ExceptionTypesTest", "IdentiferDecodeTest", "SimpleDecodeTest",
]

import unittest
from snmp.ber import *
from snmp.exception import *
from snmp.utils import subbytes

class ExceptionTypesTest(unittest.TestCase):
    def throw(self, exceptionType):
        raise exceptionType()

    def testEncodeError(self):
        self.assertRaises(SNMPException, self.throw, EncodeError)

    def testParseError(self):
        self.assertRaises(IncomingMessageError, self.throw, ParseError)

class IdentiferDecodeTest(unittest.TestCase):
    def testUniversalConstructed(self):
        identifier = Identifier(Class.UNIVERSAL, Structure.CONSTRUCTED, 16)
        self.assertEqual(decode(b"\x30\x00")[0], identifier)

    def testApplicationPrimitive(self):
        identifier = Identifier(Class.APPLICATION, Structure.PRIMITIVE, 1)
        self.assertEqual(decode(b"\x41\x00")[0], identifier)

    def testContextSpecific(self):
        identifier = Identifier(Class.CONTEXT_SPECIFIC, Structure.PRIMITIVE, 2)
        self.assertEqual(decode(b"\x82\x00")[0], identifier)

    def testHugeTag(self):
        tag = 0x1173df6
        identifier = Identifier(Class.PRIVATE, Structure.CONSTRUCTED, tag)
        self.assertEqual(decode(b"\xff\x88\xdc\xfb\x76\x00")[0], identifier)

class SimpleDecodeTest(unittest.TestCase):
    def setUp(self):
        self.data = b"\x04\x02\x00\x00"

    def testEmpty(self):
        self.assertRaises(ParseError, decode, self.data[:0])

    def testNoLength(self):
        self.assertRaises(ParseError, decode, self.data[:1])

    def testNoData(self):
        self.assertRaises(ParseError, decode, self.data[:2])

    def testTooShort(self):
        self.assertRaises(ParseError, decode, self.data[:3])

    def testTooLong(self):
        self.assertRaises(ParseError, decode, self.data + bytes(1))

    def testWrongType(self):
        identifier = Identifier(Class.UNIVERSAL, Structure.PRIMITIVE, 2)
        self.assertRaises(ParseError, decode, self.data, expected=identifier)

    def testDecode(self):
        _, data = decode(self.data)
        self.assertEqual(data, bytes(2))

class BigDecodeTest(unittest.TestCase):
    def setUp(self):
        self.data = b"\x04\x82\x01\x8a" + bytes(394)

    def testInvalidLength(self):
        self.assertRaises(ParseError, decode, self.data[:3])

    def testBigData(self):
        _, data = decode(self.data)
        self.assertEqual(data, bytes(394))

class DecodeTypesTest(unittest.TestCase):
    def testDecodeSubbytes(self):
        data = subbytes(b"nonsense\x04\x08deadbeefmorenonsense", 8, 18)
        identifier = Identifier(Class.UNIVERSAL, Structure.PRIMITIVE, 4)
        data = decode(data, expected=identifier)

        self.assertFalse(isinstance(data, subbytes))
        self.assertEqual(data, b"deadbeef")

    def testExpectedWithLeftovers(self):
        identifier = Identifier(Class.UNIVERSAL, Structure.PRIMITIVE, 4)
        result = decode(b"\x04\x02beef", expected=identifier, leftovers=True)
        data, leftovers = result

        self.assertTrue(isinstance(result, tuple))
        self.assertFalse(isinstance(data, subbytes))
        self.assertTrue(isinstance(leftovers, subbytes))

        self.assertEqual(data, b"be")
        self.assertEqual(leftovers, b"ef")

    def testMysteryLeftovers(self):
        result = decode(b"\x04\x04deadbeef", leftovers=True)
        identifier, data, leftovers = result

        self.assertTrue(isinstance(result, tuple))
        self.assertTrue(isinstance(identifier, Identifier))
        self.assertFalse(isinstance(data, subbytes))
        self.assertTrue(isinstance(leftovers, subbytes))

        self.assertEqual(
            identifier,
            Identifier(Class.UNIVERSAL, Structure.PRIMITIVE, 4)
        )

        self.assertEqual(data, b"dead")
        self.assertEqual(leftovers, b"beef")

    def testNoCopy(self):
        result = decode(b"\x04\x04deadbeef", leftovers=True, copy=False)
        identifier, data, leftovers = result

        self.assertTrue(isinstance(result, tuple))
        self.assertTrue(isinstance(identifier, Identifier))
        self.assertTrue(isinstance(data, subbytes))
        self.assertTrue(isinstance(leftovers, subbytes))

        self.assertEqual(
            identifier,
            Identifier(Class.UNIVERSAL, Structure.PRIMITIVE, 4)
        )

        self.assertEqual(data, b"dead")
        self.assertEqual(leftovers, b"beef")

class EncodeTest(unittest.TestCase):
    def testLargeTag(self):
        identifier = Identifier(Class.PRIVATE, Structure.CONSTRUCTED, 9001)
        self.assertEqual(encode(identifier, b""), b"\xff\xc6\x29\x00")

    def testLongOctetString(self):
        data = bytes(10000)
        encoding = b"\x04\x82\x27\x10" + data
        identifier = Identifier(Class.UNIVERSAL, Structure.PRIMITIVE, 4)
        self.assertEqual(encode(identifier, data), encoding)

    def testInteger(self):
        data = int(8888).to_bytes(2, "big")
        identifier = Identifier(Class.UNIVERSAL, Structure.PRIMITIVE, 2)
        self.assertEqual(encode(identifier, data), b"\x02\x02\x22\xb8")

if __name__ == '__main__':
    unittest.main()
