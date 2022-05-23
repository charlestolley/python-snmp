__all__ = [
    "Counter64Test", "IntegerTypesTest", "IpAddressTest",
    "ZeroDotZeroTest",
]

import unittest
from snmp.ber import *
from snmp.smi.v2 import Unsigned
from snmp.smi.v2 import *
from snmp.types import *
from snmp.utils import NumberGenerator

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

class IntegerTypesTest(unittest.TestCase):
    def testCounter32(self):
        result = Counter32.decode(b"\x41\x00")
        self.assertEqual(result, Counter32(0))

    def testGauge32(self):
        result = Gauge32.decode(b"\x42\x00")
        self.assertEqual(result, Gauge32(0))

    def testTimeTicks(self):
        result = TimeTicks.decode(b"\x43\x00")
        self.assertEqual(result, TimeTicks(0))

    def testCounter64(self):
        result = Counter64.decode(b"\x46\x00")
        self.assertEqual(result, Counter64(0))

class Counter32Test(unittest.TestCase):
    def setUp(self):
        self.num = 987654321

    def testRepr(self):
        counter = Counter32(self.num)
        self.assertEqual(eval(repr(counter)), counter)

    def testEquals(self):
        self.assertTrue(Counter32(self.num).equals(Integer(self.num)))

    def testNotEqual(self):
        self.assertNotEqual(Counter32(self.num), Integer(self.num))

    def testUnsigned(self):
        counter = Counter32((1<<32)-self.num)
        integer = Integer(-self.num)

        self.assertFalse(counter.equals(integer))
        self.assertEqual(
            decode(counter.encode())[1],
            decode(integer.encode())[1]
        )

    def testDecodeMax(self):
        self.assertEqual(
            Counter32.decode(b"\x41\x04\xff\xff\xff\xff"),
            Counter32((1 << 32) - 1)
        )

class Gauge32Test(unittest.TestCase):
    def setUp(self):
        self.num = 987654321

    def testRepr(self):
        gauge = Gauge32(self.num)
        self.assertEqual(eval(repr(gauge)), gauge)

    def testEquals(self):
        self.assertTrue(Gauge32(self.num).equals(Integer(self.num)))

    def testNotEqual(self):
        self.assertNotEqual(Gauge32(self.num), Integer(self.num))

    def testUnsigned(self):
        gauge = Gauge32((1<<32)-self.num)
        integer = Integer(-self.num)

        self.assertFalse(gauge.equals(integer))
        self.assertEqual(
            decode(gauge.encode())[1],
            decode(integer.encode())[1]
        )

    def testDecodeMax(self):
        self.assertEqual(
            Gauge32.decode(b"\x42\x04\xff\xff\xff\xff"),
            Gauge32((1 << 32) - 1)
        )

    def testUnsigned32(self):
        self.assertIs(Unsigned32, Gauge32)

class TimeTicksTest(unittest.TestCase):
    def setUp(self):
        self.num = 987654321

    def testRepr(self):
        ticks = TimeTicks(self.num)
        self.assertEqual(eval(repr(ticks)), ticks)

    def testEquality(self):
        self.assertTrue(TimeTicks(self.num).equals(Integer(self.num)))

    def testNotEqual(self):
        self.assertNotEqual(TimeTicks(self.num), Integer(self.num))

    def testUnsigned(self):
        ticks = TimeTicks((1<<32)-self.num)
        integer = Integer(-self.num)

        self.assertFalse(ticks.equals(integer))
        self.assertEqual(
            decode(ticks.encode())[1],
            decode(integer.encode())[1]
        )

    def testDecodeMax(self):
        self.assertEqual(
            TimeTicks.decode(b"\x43\x04\xff\xff\xff\xff"),
            TimeTicks((1 << 32) - 1)
        )

class OpaqueTest(unittest.TestCase):
    def setUp(self):
        self.data = b"this could contain anyting"

    def testEquality(self):
        self.assertTrue(Opaque(self.data).equals(OctetString(self.data)))

    def testRepr(self):
        self.assertEqual(eval(repr(Opaque(self.data))), Opaque(self.data))

class Counter64Test(unittest.TestCase):
    def helpTestDecode(self, data, value):
        result = Counter64.decode(data)
        self.assertEqual(result, Counter64(value))

    def helpTestEncode(self, n):
        result = Counter64(n).encode()
        self.assertEqual(Counter64.decode(result), Counter64(n))

    def testDecodeMax(self):
        self.helpTestDecode(b"\x46\x08" + (b"\xff" * 8), (1 << 64) - 1)

    def testDecodeOverflow(self):
        data = b"\x46\x09\x01" + (b"\x00" * 8)
        self.assertRaises(ParseError, Counter64.decode, data)

    def testEncodeMax(self):
        self.helpTestEncode((1 << 64) - 1)

    def testEncodeNegative(self):
        self.assertRaises(ValueError, Counter64(-1).encode)

    def testEncodeTooLarge(self):
        self.assertRaises(ValueError, Counter64(1 << 64).encode)

class ZeroDotZeroTest(unittest.TestCase):
    def setUp(self):
        self.data = b"\x06\x01\x00"

    def testDecode(self):
        self.assertEqual(zeroDotZero, OID.decode(self.data))

    def testEncode(self):
        self.assertEqual(zeroDotZero.encode(), self.data)

if __name__ == '__main__':
    unittest.main()
