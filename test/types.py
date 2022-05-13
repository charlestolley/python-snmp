__all__ = ["IntegerTest", "NullTest", "OIDTest", "OctetStringTest"]

import unittest
from snmp.ber import ParseError
from snmp.types import *
from snmp.utils import NumberGenerator

class IntegerTest(unittest.TestCase):
    def helpTestDecode(self, data, value):
        result = Integer.decode(data)
        self.assertTrue(isinstance(result, Integer))
        self.assertEqual(result.value, value)

    def helpTestEncode(self, n):
        result = Integer(n).encode()
        self.assertEqual(Integer.decode(result).value, n)

    def testDecodeEmpty(self):
        self.helpTestDecode(b"\x02\x00", 0)

    def testDecodeByte(self):
        self.helpTestDecode(b"\x02\x01i", ord("i"))

    def testDecodeIntMax(self):
        self.helpTestDecode(b"\x02\x04\x7f\xff\xff\xff", (1 << 31) - 1)

    def testDecodeIntMin(self):
        self.helpTestDecode(b"\x02\x04\x80\x00\x00\x00", -(1 << 31))

    def testDecodeOverflow(self):
        data = b"\x02\x05\x01\x00\x00\x00\x00"
        self.assertRaises(ParseError, Integer.decode, data)

    def testDecodeOversized(self):
        result = Integer.decode(b"\x02\x06\x00\x00asdf")
        self.assertTrue(isinstance(result, Integer))
        self.assertLess(result.value, 1 << 31)
        self.assertGreaterEqual(result.value, -(1 << 31))

    def testEncodeZero(self):
        self.helpTestEncode(0)

    def testEncodeRandom(self):
        generator = NumberGenerator(32, signed=True)
        self.helpTestEncode(next(generator))

    def testEncodeIntMax(self):
        self.helpTestEncode((1 << 31) - 1)

    def testEncodeIntMin(self):
        self.helpTestEncode(-(1 << 31))

    def testEncodeTooLarge(self):
        self.assertRaises(ValueError, self.helpTestEncode, 1 << 31)

class OctetStringTest(unittest.TestCase):
    def testDecodeEmpty(self):
        result = OctetString.decode(b"\x04\x00")
        self.assertEqual(result.data, b"")

    def testDecodeSomething(self):
        result = OctetString.decode(b"\x04\x09something")
        self.assertEqual(result.data, b"something")

    def testDecodeLongString(self):
        result = OctetString.decode(b"\x04\x82\x03\xe7" + (999 * b"\x00"))
        self.assertEqual(result.data, 999 * b"\x00")

    def testEncodeEmpty(self):
        self.assertEqual(OctetString().encode(), b"\x04\x00")

    def testEncodeSomething(self):
        result = OctetString(b"something").encode()
        self.assertEqual(result, b"\x04\x09something")

    def testEncodeLongString(self):
        result = OctetString(999 * b"\x00").encode()
        self.assertEqual(result, b"\x04\x82\x03\xe7" + (999 * b"\x00"))

class NullTest(unittest.TestCase):
    def testDecodeEmpty(self):
        self.assertTrue(isinstance(Null.decode(b"\x05\x00"), Null))

    def testDecodeNonEmpty(self):
        self.assertTrue(isinstance(Null.decode(b"\x05\x08nonsense"), Null))

    def testEncode(self):
        self.assertEqual(Null().encode(), b"\x05\x00")

class OIDTest(unittest.TestCase):
    def __init__(self, *args):
        super().__init__(*args)
        self.internet = OID(1, 3, 6, 1)

    def testLength(self):
        self.assertEqual(len(self.internet), 4)

    def testIndex(self):
        self.assertEqual(self.internet[0], 1)
        self.assertEqual(self.internet[1], 3)
        self.assertEqual(self.internet[2], 6)
        self.assertEqual(self.internet[3], 1)

    def testStr(self):
        self.assertEqual(str(self.internet), "1.3.6.1")

    def testRepr(self):
        self.assertEqual(eval(repr(self.internet)), self.internet)

    def testEqual(self):
        self.assertEqual(OID(1, 3, 6, 1), self.internet)

    def testNotEqual(self):
        self.assertNotEqual(OID(1, 3, 5, 1), self.internet)

    def testNotEqualLong(self):
        self.assertNotEqual(OID(1, 3, 6, 1, 2), self.internet)

    def testNotEqualShort(self):
        self.assertNotEqual(OID(1, 3, 6), self.internet)

    def testParseDot(self):
        self.assertEqual(OID.parse(".1.3.6.1"), self.internet)

    def testParseNoDot(self):
        self.assertEqual(OID.parse("1.3.6.1"), self.internet)

    def testParseEmpty(self):
        self.assertRaises(ValueError, OID.parse, "")

    def testParseShort(self):
        self.assertRaises(ValueError, OID.parse, "1")

    def testParseLong(self):
        oid = ".".join("1" for _ in range(200))
        self.assertRaises(ValueError, OID.parse, oid)

    def testParseInvalidFirst(self):
        self.assertRaises(ValueError, OID.parse, "5.3")

    def testParseInvalidSecond(self):
        self.assertRaises(ValueError, OID.parse, "1.89")

    def testParseNegative(self):
        self.assertRaises(ValueError, OID.parse, "1.3.-6.1")

    def testParseOutOfRange(self):
        self.assertRaises(ValueError, OID.parse, "1.3.6.1.{}".format(1 << 32))

    def testParseGarbage(self):
        self.assertRaises(ValueError, OID.parse, "clearly not an OID string")

    def testExtendIsConst(self):
        _ = self.internet.extend(1)
        self.assertEqual(self.internet, OID(1, 3, 6, 1))

    def testExtendOne(self):
        self.assertEqual(self.internet.extend(2), OID(1, 3, 6, 1, 2))

    def testExtendMany(self):
        oid = self.internet.extend(2, 1, 1, 1, 0)
        self.assertEqual(oid, OID(1, 3, 6, 1, 2, 1, 1, 1, 0))

    def testDecodeEmpty(self):
        self.assertRaises(ParseError, OID.decode, b"\x06\x00")

    def testDecodeZero(self):
        self.assertEqual(OID(0, 0), OID.decode(b"\x06\x01\x00"))

    def testDecodeShort(self):
        self.assertEqual(OID(1, 0), OID.decode(b"\x06\x01\x28"))

    def testDecodeInternet(self):
        self.assertEqual(self.internet, OID.decode(b"\x06\x03\x2b\x06\x01"))

    def testDecodeLarge(self):
        oid = OID.decode(b"\x06\x08\x28\xc4\x62\x01\x01\x02\x01\x01")
        self.assertEqual(oid, OID(1, 0, 8802, 1, 1, 2, 1, 1))

    def testDecodeAlmostTooLarge(self):
        encoding = b"\x06\x06\x2b\x8f\xff\xff\xff\x7f"
        self.assertEqual(OID.decode(encoding), OID(1, 3, (1<<32)-1))

    def testDecodeTooLarge(self):
        encoding = b"\x06\x06\x2b\x90\x80\x80\x80\x00"
        self.assertRaises(ParseError, OID.decode, encoding)

    def testDecodeWayTooLarge(self):
        encoding = b"\x06\x06\x2b\xff\xff\xff\xff\x7f"
        self.assertRaises(ParseError, OID.decode, encoding)

    def testEncodeEmpty(self):
        self.assertEqual(OID().encode(), b"\x06\x01\x00")

    def testEncodeShort(self):
        self.assertEqual(OID(1).encode(), b"\x06\x01\x28")

    def testEncodeInternet(self):
        self.assertEqual(self.internet.encode(), b"\x06\x03\x2b\x06\x01")

    def testEncodeLarge(self):
        encoding = OID(1, 0, 8802, 1, 1, 2, 1, 1).encode()
        self.assertEqual(encoding, b"\x06\x08\x28\xc4\x62\x01\x01\x02\x01\x01")

    def testEncodeAlmostTooLarge(self):
        encoding = OID(1, 3, (1<<32)-1).encode()
        self.assertEqual(encoding, b"\x06\x06\x2b\x8f\xff\xff\xff\x7f")

    def testExtractInteger(self):
        oid = self.internet.extend(3)
        index = oid.extractIndex(self.internet, Integer)
        self.assertTrue(isinstance(index, Integer))
        self.assertEqual(index.value, 3)

    def testExtractIntegerOutOfRange(self):
        oid = self.internet.extend(1 << 31)
        self.assertRaises(
            OID.IndexDecodeError,
            oid.extractIndex,
            self.internet,
        )

    def testExtractOctetString(self):
        data = b"test string"
        oid = self.internet.extend(len(data), *data)
        result = oid.extractIndex(self.internet, OctetString)
        self.assertTrue(isinstance(result, OctetString))
        self.assertEqual(data, result.data)

    def testExtractIncompleteOctetString(self):
        data = b"test string"
        oid = self.internet.extend(len(data) + 1, *data)
        self.assertRaises(
            OID.IndexDecodeError,
            oid.extractIndex,
            self.internet,
            OctetString,
        )

    def testExtractInvalidOctets(self):
        oid = self.internet.extend(3, ord("O"), ord("I"), 394)
        self.assertRaises(
            OID.IndexDecodeError,
            oid.extractIndex,
            self.internet,
            OctetString,
        )

    def testExtractOID(self):
        oid = self.internet.extend(len(self.internet), *self.internet)
        result = oid.extractIndex(self.internet, OID)
        self.assertEqual(result, self.internet)

    def testExtractIncompleteOID(self):
        oid = self.internet.extend(len(self.internet) + 1, *self.internet)
        self.assertRaises(
            OID.IndexDecodeError,
            oid.extractIndex,
            self.internet,
            OID,
        )

    def testExtractOversizedPrefix(self):
        sysDescr = OID(1, 3, 6, 1, 2, 1, 1, 1)
        self.assertRaises(
            OID.BadPrefix,
            self.internet.extractIndex,
            sysDescr,
        )

    def testExtractWrongPrefix(self):
        self.assertRaises(
            OID.BadPrefix,
            self.internet.extractIndex,
            OID(1, 4, 9),
            Integer,
        )

    def testExtractLeftovers(self):
        oid = self.internet.extend(3, 0)
        self.assertRaises(
            OID.IndexDecodeError,
            oid.extractIndex,
            self.internet,
            Integer,
        )

    def testExtractMatched(self):
        self.assertEqual(None, self.internet.extractIndex(self.internet))

    def testExtractMissing(self):
        self.assertRaises(
            OID.IndexDecodeError,
            self.internet.extractIndex,
            self.internet,
            Integer,
        )

    def testExtractMany(self):
        inetCidrRouteIfIndex = OID(1, 3, 6, 1, 2, 1, 4, 24, 7, 1, 7)
        oid = inetCidrRouteIfIndex      \
            .extend(1)                  \
            .extend(4, 192, 168, 0, 0)  \
            .extend(24)                 \
            .extend(3, 0, 0, 2)         \
            .extend(1)                  \
            .extend(4, 0, 0, 0, 0)

        destType, dest, pfxLen, policy, nextHopType, nextHop = oid.extractIndex(
            inetCidrRouteIfIndex,
            Integer, OctetString, Integer, OID, Integer, OctetString,
        )

        self.assertTrue(isinstance(destType, Integer))
        self.assertTrue(isinstance(dest, OctetString))
        self.assertTrue(isinstance(pfxLen, Integer))
        self.assertTrue(isinstance(policy, OID))
        self.assertTrue(isinstance(nextHopType, Integer))
        self.assertTrue(isinstance(nextHop, OctetString))

        self.assertEqual(destType.value, 1)
        self.assertEqual(dest.data, b"\xc0\xa8\x00\x00")
        self.assertEqual(pfxLen.value, 24)
        self.assertEqual(policy, OID(0, 0, 2))
        self.assertEqual(nextHopType.value, 1)
        self.assertEqual(nextHop.data, b"\x00\x00\x00\x00")

    def testAppendZero(self):
        oid = self.internet.appendIndex(Integer(0))
        self.assertEqual(oid, OID(1, 3, 6, 1, 0))

    def testAppendInteger(self):
        oid = self.internet.appendIndex(Integer(409))
        self.assertEqual(oid, OID(1, 3, 6, 1, 409))

    def testAppendOctetString(self):
        oid = self.internet.appendIndex(OctetString(b"index"))
        self.assertEqual(oid, OID(1, 3, 6, 1, 5, 0x69, 0x6e, 0x64, 0x65, 0x78))

    def testAppendOID(self):
        oid = self.internet.appendIndex(self.internet)
        self.assertEqual(oid, OID(1, 3, 6, 1, 4, 1, 3, 6, 1))

    def testAppendMany(self):
        oid = self.internet.appendIndex(Integer(42), OctetString(b"Robinson"))
        self.assertEqual(oid, OID(
            1, 3, 6, 1, 42, 8, 0x52, 0x6f, 0x62, 0x69, 0x6e, 0x73, 0x6f, 0x6e
        ))

if __name__ == '__main__':
    unittest.main()
