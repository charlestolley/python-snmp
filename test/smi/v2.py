__all__ = [
    "Counter64Test", "IntegerTypesTest", "IpAddressTest",
    "UnsignedTest", "ZeroDotZeroTest",
]

import unittest
from snmp.ber import ParseError
from snmp.smi.v2 import Unsigned
from snmp.smi.v2 import *
from snmp.types import OID
from snmp.utils import NumberGenerator

class UnsignedTest(unittest.TestCase):
    def helpTestDecode(self, data, value):
        result = Unsigned.decode(data)
        self.assertTrue(isinstance(result, Unsigned))
        self.assertEqual(result.value, value)

    def helpTestEncode(self, n):
        result = Unsigned(n).encode()
        self.assertEqual(Unsigned.decode(result).value, n)

    def testDecodeEmpty(self):
        self.helpTestDecode(b"\x02\x00", 0)

    def testDecodeZero(self):
        self.helpTestDecode(b"\x02\x01\x00", 0)

    def testDecodeMax(self):
        self.helpTestDecode(b"\x02\x04\xff\xff\xff\xff", (1 << 32) - 1)

    def testDecodeOverflow(self):
        data = b"\x02\x05\x01\x00\x00\x00\x00"
        self.assertRaises(ParseError, Unsigned.decode, data)

    def testEncodeZero(self):
        self.helpTestEncode(0)

    def testEncodeRandom(self):
        generator = NumberGenerator(32, signed=False)
        self.helpTestEncode(next(generator))

    def testEncodeMax(self):
        self.helpTestEncode((1 << 32) - 1)

    def testEncodeNegative(self):
        self.assertRaises(ValueError, Unsigned(-1).encode)

    def testEncodeTooLarge(self):
        self.assertRaises(ValueError, Unsigned(1 << 32).encode)

class IpAddressTest(unittest.TestCase):
    def setUp(self):
        self.addr = "12.34.56.78"
        self.data = b"\x40\x04\x0c\x22\x38\x4e"

    def testEqual(self):
        self.assertEqual(IpAddress(self.addr), IpAddress(self.addr))

    def testRepr(self):
        addr = IpAddress(self.addr)
        self.assertEqual(eval(repr(addr)), addr)

    def testDecode(self):
        self.assertEqual(IpAddress.decode(self.data).addr, self.addr)

    def testDecodeTooShort(self):
        self.assertRaises(ParseError, IpAddress.decode, b"\x40\x03abc")

    def testDecodeTooLong(self):
        self.assertRaises(ParseError, IpAddress.decode, b"\x40\x05badIP")

    def testEncode(self):
        self.assertEqual(IpAddress(self.addr).encode(), self.data)

class IntegerTypesTest(unittest.TestCase):
    def testCounter32(self):
        result = Counter32.decode(b"\x41\x00")
        self.assertTrue(isinstance(result, Counter32))
        self.assertEqual(result.value, 0)

    def testGauge32(self):
        result = Gauge32.decode(b"\x42\x00")
        self.assertTrue(isinstance(result, Gauge32))
        self.assertEqual(result.value, 0)

    def testTimeTicks(self):
        result = TimeTicks.decode(b"\x43\x00")
        self.assertTrue(isinstance(result, TimeTicks))
        self.assertEqual(result.value, 0)

    def testCounter64(self):
        result = Counter64.decode(b"\x46\x00")
        self.assertTrue(isinstance(result, Counter64))
        self.assertEqual(result.value, 0)

class Counter64Test(unittest.TestCase):
    def helpTestDecode(self, data, value):
        result = Counter64.decode(data)
        self.assertTrue(isinstance(result, Counter64))
        self.assertEqual(result.value, value)

    def helpTestEncode(self, n):
        result = Counter64(n).encode()
        self.assertEqual(Counter64.decode(result).value, n)

    def testDecodeMax(self):
        self.helpTestDecode(b"\x46\x08" + (b"\xff" * 8), (1 << 64) - 1)

    def testDecodeOverflow(self):
        data = b"\x46\x09\x01" + (b"\x00" * 8)
        self.assertRaises(ParseError, Counter64.decode, data)

    def testEncodeZero(self):
        self.helpTestEncode(0)

    def testEncodeRandom(self):
        generator = NumberGenerator(64, signed=False)
        self.helpTestEncode(next(generator))

    def testEncodeMax(self):
        self.helpTestEncode((1 << 64) - 1)

    def testEncodeNegative(self):
        self.assertRaises(ValueError, Unsigned(-1).encode)

    def testEncodeTooLarge(self):
        self.assertRaises(ValueError, Unsigned(1 << 64).encode)

class ZeroDotZeroTest(unittest.TestCase):
    def setUp(self):
        self.data = b"\x06\x01\x00"

    def testDecode(self):
        self.assertEqual(zeroDotZero, OID.decode(self.data))

    def testEncode(self):
        self.assertEqual(zeroDotZero.encode(), self.data)

if __name__ == '__main__':
    unittest.main()
