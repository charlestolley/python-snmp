__all__ = [
    "IdentifierTest", "IntegerTest", "NullTest", "OIDTest", "OctetStringTest"
]

import unittest
from snmp.ber import *
from snmp.types import *
from snmp.utils import NumberGenerator

class IdentifierTest(unittest.TestCase):
    def testInteger(self):
        self.assertEqual(decode(b"\x02\x00")[0], INTEGER)

    def testOctetString(self):
        self.assertEqual(decode(b"\x04\x00")[0], OCTET_STRING)

    def testNull(self):
        self.assertEqual(decode(b"\x05\x00")[0], NULL)

    def testObjectIdentifier(self):
        self.assertEqual(decode(b"\x06\x00")[0], OBJECT_IDENTIFIER)

    def testSequence(self):
        self.assertEqual(decode(b"\x30\x00")[0], SEQUENCE)

class IntegerTest(unittest.TestCase):
    def setUp(self):
        self.MIN = -(1 << 31)
        self.MAX = (1 << 31) - 1

    def helpTestDecode(self, data, value):
        self.assertEqual(Integer.decode(data), Integer(value))

    def helpTestEncode(self, n):
        # There may be multiple valid ways to encode a number,
        # but as long as decode() has been tested, there's no
        # reason not to use it to test encode().
        n = Integer(n)
        self.assertEqual(Integer.decode(n.encode()), n)

    def testNotEqual(self):
        self.assertNotEqual(Integer(4), Integer(9))

    def testWrongType(self):
        self.assertNotEqual(Integer(0), OctetString(bytes(1)))

    def testRepr(self):
        integer = Integer(2704)
        self.assertEqual(eval(repr(integer)), integer)

    def testDecodeEmpty(self):
        self.helpTestDecode(encode(INTEGER, b""), 0)

    def testDecodeByte(self):
        self.helpTestDecode(encode(INTEGER, b"i"), ord("i"))

    def testDecodeMax(self):
        self.helpTestDecode(encode(INTEGER, b"\x7f\xff\xff\xff"), self.MAX)

    def testDecodeMin(self):
        self.helpTestDecode(encode(INTEGER, b"\x80\x00\x00\x00"), self.MIN)

    def testDecodeOverflow(self):
        data = encode(INTEGER, b"\x01\x00\x00\x00\x00")
        self.assertRaises(ParseError, Integer.decode, data)

    def testDecodeOversized(self):
        result = Integer.decode(encode(INTEGER, b"\x00\x00asdf"))
        self.assertTrue(isinstance(result, Integer))
        self.assertLessEqual(result.value, self.MAX)
        self.assertGreaterEqual(result.value, self.MIN)

    def testDecodeTwo(self):
        data = encode(INTEGER, b"four") + encode(INTEGER, b"char")
        a, data = Integer.decode(data, leftovers=True)
        b, data = Integer.decode(data, leftovers=True)
        self.assertEqual(a, Integer(0x666f7572))
        self.assertEqual(b, Integer(0x63686172))
        self.assertEqual(data, b"")

    def testEncodeZero(self):
        self.helpTestEncode(0)

    def testEncodeNonZero(self):
        self.helpTestEncode(1066)

    def testEncodeMax(self):
        self.helpTestEncode(self.MAX)

    def testEncodeMin(self):
        self.helpTestEncode(self.MIN)

class OctetStringTest(unittest.TestCase):
    def setUp(self):
        self.MAXLEN = 0xffff

    def helpTestDecode(self, s):
        data = encode(OCTET_STRING, s)
        self.assertEqual(OctetString.decode(data), OctetString(s))

    def helpTestEncode(self, s):
        self.assertEqual(OctetString(s).encode(), encode(OCTET_STRING, s))

    def testNotEqual(self):
        self.assertNotEqual(OctetString(b"string1"), OctetString(b"StringTwo"))

    def testWrongType(self):
        self.assertNotEqual(OctetString(), Null())

    def testRepr(self):
        string = OctetString(b"gnirtStetcO")
        self.assertEqual(eval(repr(string)), string)

    def testDecodeEmpty(self):
        self.helpTestDecode(b"")

    def testDecodeSomething(self):
        self.helpTestDecode(b"something")

    def testMaxString(self):
        self.helpTestDecode(bytes(self.MAXLEN))

    def testOversizedString(self):
        data = encode(OCTET_STRING, bytes(self.MAXLEN + 1))
        self.assertRaises(ParseError, OctetString.decode, data)

    def testEncodeEmpty(self):
        self.helpTestEncode(b"")

    def testEncodeSomething(self):
        self.helpTestEncode(b"something")

    def testEncodeMaxString(self):
        self.helpTestEncode(bytes(self.MAXLEN))

    def testEncodeOversizedString(self):
        data = bytes(self.MAXLEN + 1)
        self.assertRaises(ValueError, OctetString(data).encode)

class NullTest(unittest.TestCase):
    def helpTestDecode(self, data):
        self.assertEqual(Null.decode(data), Null())

    def testWrongType(self):
        self.assertNotEqual(Null(), OID())

    def testRepr(self):
        null = Null()
        self.assertEqual(eval(repr(null)), null)

    def testDecodeEmpty(self):
        self.helpTestDecode(encode(NULL, b""))

    def testDecodeNonEmpty(self):
        self.helpTestDecode(encode(NULL, b"nonsense"))

    def testEncode(self):
        self.assertEqual(Null().encode(), encode(NULL, b""))

class OIDTest(unittest.TestCase):
    def setUp(self):
        self.internet = OID(1, 3, 6, 1)

    def testNotEqual(self):
        self.assertNotEqual(OID(1, 3, 5, 1), self.internet)

    def testWrongType(self):
        self.assertNotEqual(self.internet, Integer(1361))

    def testRepr(self):
        self.assertEqual(eval(repr(self.internet)), self.internet)

    def testStr(self):
        self.assertEqual(OID.parse(str(self.internet)), self.internet)

    def testGetItem(self):
        self.assertEqual(self.internet[0], 1)
        self.assertEqual(self.internet[1], 3)
        self.assertEqual(self.internet[2], 6)
        self.assertEqual(self.internet[3], 1)
        self.assertRaises(IndexError, self.internet.__getitem__, 4)

    def testHash(self):
        table = {self.internet: None}
        self.assertIn(OID(1, 3, 6, 1), table)

    def testLen(self):
        self.assertEqual(len(self.internet), 4)

    def testParseDot(self):
        self.assertEqual(OID.parse(".1.3.6.1"), self.internet)

    def testParseNoDot(self):
        self.assertEqual(OID.parse("1.3.6.1"), self.internet)

    def testParseRoot(self):
        self.assertEqual(OID.parse("."), OID())

    def testParseEmpty(self):
        self.assertEqual(OID.parse(""), OID())

    def testParseShort(self):
        self.assertEqual(OID.parse("1"), OID(1))

    def testParseValidFirst(self):
        self.assertEqual(OID.parse("2.3"), OID(2, 3))

    def testParseInvalidFirst(self):
        self.assertRaises(ValueError, OID.parse, "3.3")

    def testParseValidSecond(self):
        self.assertEqual(OID.parse("1.39"), OID(1, 39))

    def testParseInvalidSecond(self):
        self.assertRaises(ValueError, OID.parse, "1.40")

    def testParseMaxValue(self):
        self.assertEqual(
            self.internet.extend((1 << 32) - 1),
            OID.parse(f"1.3.6.1.{(1<<32)-1}")
        )

    def testParseNegative(self):
        self.assertRaises(ValueError, OID.parse, "1.3.6.-1")

    def testParseOutOfRange(self):
        self.assertRaises(ValueError, OID.parse, f"1.3.6.1.{1<<32}")

    def testParseMaxLength(self):
        oid = ".".join("1" for n in range(128))
        self.assertEqual(OID.parse(oid), OID(*((1,) * 128)))

    def testParseTooLong(self):
        oid = ".".join("1" for n in range(129))
        self.assertRaises(ValueError, OID.parse, oid)

    def testParseGarbage(self):
        self.assertRaises(ValueError, OID.parse, "clearly not an OID string")

    def testExtendOne(self):
        self.assertEqual(self.internet.extend(2), OID(1, 3, 6, 1, 2))

    def testExtendMany(self):
        oid = self.internet.extend(2, 1, 1, 1, 0)
        self.assertEqual(oid, OID(1, 3, 6, 1, 2, 1, 1, 1, 0))

    def testAppendZero(self):
        oid = self.internet.appendIndex(Integer(0))
        self.assertEqual(oid, OID(1, 3, 6, 1, 0))

    def testAppendInteger(self):
        oid = self.internet.appendIndex(Integer(409))
        self.assertEqual(oid, OID(1, 3, 6, 1, 409))

    def testAppendOctetString(self):
        oid = self.internet.appendIndex(OctetString(b"index"))
        self.assertEqual(oid, OID(1, 3, 6, 1, 5, 0x69, 0x6e, 0x64, 0x65, 0x78))

    def testAppendNull(self):
        self.assertEqual(self.internet.appendIndex(Null()), self.internet)

    def testAppendOID(self):
        oid = self.internet.appendIndex(self.internet)
        self.assertEqual(oid, OID(1, 3, 6, 1, 4, 1, 3, 6, 1))

    def testAppendMany(self):
        oid = self.internet.appendIndex(Integer(42), OctetString(b"Robinson"))
        self.assertEqual(oid, OID(
            1, 3, 6, 1, 42, 8, 0x52, 0x6f, 0x62, 0x69, 0x6e, 0x73, 0x6f, 0x6e
        ))

    def testIndexDefault(self):
        oid = self.internet.extend(3)
        index = oid.getIndex(self.internet)
        self.assertEqual(index, Integer(3))

    def testIndexInteger(self):
        oid = self.internet.extend(3)
        index = oid.getIndex(self.internet, Integer)
        self.assertEqual(index, Integer(3))

    def testIndexIntegerOutOfRange(self):
        oid = self.internet.extend(1 << 31)
        self.assertRaises(
            OID.IndexDecodeError,
            oid.getIndex,
            self.internet,
            Integer,
        )

    def testIndexOctetString(self):
        data = b"test string"
        oid = self.internet.extend(len(data), *data)
        result = oid.getIndex(self.internet, OctetString)
        self.assertEqual(result, OctetString(data))

    def testIndexIncompleteOctetString(self):
        data = b"test string"
        oid = self.internet.extend(len(data) + 1, *data)
        self.assertRaises(
            OID.IndexDecodeError,
            oid.getIndex,
            self.internet,
            OctetString,
        )

    def testIndexInvalidOctets(self):
        oid = self.internet.extend(3, ord("O"), ord("I"), 394)
        self.assertRaises(
            OID.IndexDecodeError,
            oid.getIndex,
            self.internet,
            OctetString,
        )

    def testIndexNull(self):
        self.assertEqual(self.internet.getIndex(self.internet, Null), Null())

    def testIndexOID(self):
        oid = self.internet.extend(len(self.internet), *self.internet)
        self.assertEqual(oid.getIndex(self.internet, OID), self.internet)

    def testIndexIncompleteOID(self):
        oid = self.internet.extend(len(self.internet) + 1, *self.internet)
        self.assertRaises(
            OID.IndexDecodeError,
            oid.getIndex,
            self.internet,
            OID,
        )

    def testIndexMissing(self):
        self.assertRaises(
            OID.IndexDecodeError,
            self.internet.getIndex,
            self.internet,
            Integer,
        )

    def testIndexLeftovers(self):
        oid = self.internet.extend(3, 0)
        self.assertRaises(
            OID.IndexDecodeError,
            oid.getIndex,
            self.internet,
            Integer,
        )

    def testExtractWrongPrefix(self):
        self.assertRaises(
            OID.BadPrefix,
            self.internet.extractIndex,
            OID(1, 4, 9, 6),
        )

    def testExtractOversizedPrefix(self):
        sysDescr = OID(1, 3, 6, 1, 2, 1, 1, 1)
        self.assertRaises(
            OID.BadPrefix,
            self.internet.extractIndex,
            sysDescr,
        )

    def testExtractMatched(self):
        self.assertEqual((), self.internet.extractIndex(self.internet))

    def testExtractOne(self):
        oid = self.internet.extend(3)
        index = oid.extractIndex(self.internet, Integer)
        self.assertEqual(index, (Integer(3),))

    def testExtractMany(self):
        inetCidrRouteIfIndex = OID(1, 3, 6, 1, 2, 1, 4, 24, 7, 1, 7)
        oid = inetCidrRouteIfIndex      \
            .extend(1)                  \
            .extend(4, 192, 168, 0, 0)  \
            .extend(24)                 \
            .extend(3, 0, 0, 2)         \
            .extend(1)                  \
            .extend(4, 0, 0, 0, 0)

        destType, dest, mask, policy, nextHopType, nextHop = oid.extractIndex(
            inetCidrRouteIfIndex,
            Integer, OctetString, Integer, OID, Integer, OctetString,
        )

        self.assertEqual(destType, Integer(1))
        self.assertEqual(dest, OctetString(b"\xc0\xa8\x00\x00"))
        self.assertEqual(mask, Integer(24))
        self.assertEqual(policy, OID(0, 0, 2))
        self.assertEqual(nextHopType, Integer(1))
        self.assertEqual(nextHop, OctetString(b"\x00\x00\x00\x00"))

    def testDecodeEmpty(self):
        data = encode(OBJECT_IDENTIFIER, b"")
        self.assertRaises(ParseError, OID.decode, data)

    def testDecodeZero(self):
        data = encode(OBJECT_IDENTIFIER, b"\x00")
        self.assertEqual(OID(0, 0), OID.decode(data))

    def testDecodeShort(self):
        data = encode(OBJECT_IDENTIFIER, b"\x28")
        self.assertEqual(OID(1, 0), OID.decode(data))

    def testDecodeInternet(self):
        data = encode(OBJECT_IDENTIFIER, b"\x2b\x06\x01")
        self.assertEqual(self.internet, OID.decode(data))

    def testDecodeLarge(self):
        data = encode(OBJECT_IDENTIFIER, b"\x28\xc4\x62\x01\x01\x02\x01\x01")
        self.assertEqual(OID.decode(data), OID(1, 0, 8802, 1, 1, 2, 1, 1))

    def testDecodeAlmostTooLarge(self):
        data = encode(OBJECT_IDENTIFIER, b"\x2b\x8f\xff\xff\xff\x7f")
        self.assertEqual(OID.decode(data), OID(1, 3, (1<<32)-1))

    def testDecodeTooLarge(self):
        data = encode(OBJECT_IDENTIFIER, b"\x2b\x90\x80\x80\x80\x00")
        self.assertRaises(ParseError, OID.decode, data)

    def testEncodeEmpty(self):
        self.assertEqual(OID().encode(), encode(OBJECT_IDENTIFIER, b"\x00"))

    def testEncodeShort(self):
        self.assertEqual(OID(1).encode(), encode(OBJECT_IDENTIFIER, b"\x28"))

    def testEncodeInternet(self):
        data = encode(OBJECT_IDENTIFIER, b"\x2b\x06\x01")
        self.assertEqual(self.internet.encode(), data)

    def testEncodeLarge(self):
        data = encode(OBJECT_IDENTIFIER, b"\x28\xc4\x62\x01\x01\x02\x01\x01")
        self.assertEqual(OID(1, 0, 8802, 1, 1, 2, 1, 1).encode(), data)

    def testEncodeAlmostTooLarge(self):
        data = encode(OBJECT_IDENTIFIER, b"\x2b\x8f\xff\xff\xff\x7f")
        self.assertEqual(OID(1, 3, (1<<32)-1).encode(), data)

if __name__ == '__main__':
    unittest.main()
