__all__ = [
    "DummyLockTest", "NumberGeneratorTest", "SubbytesTest", "TypenameTest",
]

import unittest
import snmp.utils

class DummyLockTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lock = snmp.utils.DummyLock()

    def testContext(self):
        with self.lock as tmp:
            self.assertIs(tmp, self.lock)

    def testAcquireRelease(self):
        self.assertTrue(self.lock.acquire())
        self.lock.release()

class TypenameTest(unittest.TestCase):
    def testQualifiedClass(self):
        self.assertEqual(
            snmp.utils.typename(self.__class__, qualified=False),
            self.__class__.__name__
        )

    def testQualifiedObject(self):
        self.assertEqual(
            snmp.utils.typename(self, qualified=False),
            self.__class__.__name__
        )

    def testUnqualifiedClass(self):
        self.assertEqual(
            snmp.utils.typename(self.__class__, qualified=True),
            ".".join((__name__, self.__class__.__name__))
        )

    def testUnqualifiedObject(self):
        self.assertEqual(
            snmp.utils.typename(self, qualified=True),
            ".".join((__name__, self.__class__.__name__))
        )

class NumberGeneratorTest(unittest.TestCase):
    N = 4

    def testSignedRange(self):
        rangeSize = 1 << self.N
        upper = (rangeSize // 2)
        lower = -upper

        generator = snmp.utils.NumberGenerator(self.N, signed=True)
        for i in range(rangeSize):
            num = next(generator)
            self.assertLess(num, upper)
            self.assertGreaterEqual(num, lower)

    def testSignedRepeat(self):
        generator = snmp.utils.NumberGenerator(self.N, signed=True)
        first = next(generator)
        for i in range((1 << self.N) - 1):
            self.assertNotEqual(next(generator), first)

    def testUnsignedRange(self):
        rangeSize = 1 << self.N
        generator = snmp.utils.NumberGenerator(self.N, signed=False)
        for i in range(rangeSize):
            num = next(generator)
            self.assertLess(num, rangeSize)
            self.assertGreaterEqual(num, 0)

    def testUnsignedRepeat(self):
        generator = snmp.utils.NumberGenerator(self.N, signed=False)
        first = next(generator)
        for i in range((1 << self.N) - 1):
            self.assertNotEqual(next(generator), first)

class SubbytesTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data = b"the quick brown fox jumps over the lazy dog"
        self.start = 4
        self.end = 25
        self.step = 3
        self.a = 6
        self.b = 15

    def testLength(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(len(self.data), len(data))

    def testBoundedLength(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(len(substring), len(data))

    def testEquality(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(self.data, data)

    def testBoundedEquality(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(substring, data)

    def testIterator(self):
        data = snmp.utils.subbytes(self.data)
        for (a, b) in zip(self.data, data):
            self.assertEqual(a, b)

    def testBoundedIterator(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        for (a, b) in zip(substring, data):
            self.assertEqual(a, b)

    def testRepr(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(self.data, eval(repr(data)))

    def testBoundedRepr(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(substring, eval(repr(data)))

    def testTrue(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(bool(substring), bool(data))

    def testFalse(self):
        data = snmp.utils.subbytes(self.data, self.end, self.start)
        substring = self.data[self.end:self.start]
        self.assertEqual(bool(substring), bool(data))

    def testPositiveIntegerIndex(self):
        data = snmp.utils.subbytes(self.data)

        i = 0
        while i < len(self.data):
            self.assertEqual(self.data[i], data[i])
            i += 1

        self.assertRaises(IndexError, data.__getitem__, i)

    def testBoundedPositiveIntegerIndex(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]

        i = 0
        while i < len(substring):
            self.assertEqual(substring[i], data[i])
            i += 1

        self.assertRaises(IndexError, data.__getitem__, i)

    def testNegativeIntegerIndex(self):
        data = snmp.utils.subbytes(self.data)

        i = -1
        while -i <= len(self.data):
            self.assertEqual(self.data[i], data[i])
            i -= 1

        self.assertRaises(IndexError, data.__getitem__, i)

    def testBoundedNegativeIntegerIndex(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]

        i = -1
        while -i <= len(substring):
            self.assertEqual(substring[i], data[i])
            i -= 1

        self.assertRaises(IndexError, data.__getitem__, i)

    def testSetItem(self):
        data = snmp.utils.subbytes(bytearray(self.data))
        data[self.start] += 1
        self.assertNotEqual(self.data, data)

    def testBoundedSetItem(self):
        data = snmp.utils.subbytes(bytearray(self.data), self.start, self.end)
        substring = bytearray(self.data[self.start:self.end])
        data     [self.a] += 1
        substring[self.a] += 1
        self.assertEqual(substring, data)

    def testConsume(self):
        data = snmp.utils.subbytes(self.data)
        byte = data.consume()
        self.assertEqual(self.data[0], byte)
        self.assertEqual(self.data[1:], data)

    def testBoundedConsume(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        byte = data.consume()
        self.assertEqual(substring[0], byte)
        self.assertEqual(substring[1:], data)

    def testEmptyConsume(self):
        data = snmp.utils.subbytes(self.data, self.start, self.start)
        self.assertRaises(IndexError, data.consume)

    def testDereference(self):
        data = snmp.utils.subbytes(self.data)
        byte = data.dereference()
        self.assertEqual(self.data[0], byte)
        self.assertEqual(self.data, data)

    def testBoundedDereference(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        byte = data.dereference()
        self.assertEqual(substring[0], byte)
        self.assertEqual(substring, data)

    def testEmptyDereference(self):
        data = snmp.utils.subbytes(self.data, self.start, self.start)
        self.assertRaises(IndexError, data.dereference)

    def testPrune(self):
        data = snmp.utils.subbytes(self.data)
        tail = data.prune(self.end)
        self.assertEqual(self.data[:self.end], data)
        self.assertEqual(self.data[self.end:], tail)

    def testSliceByConstructor(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        sliced = snmp.utils.subbytes(data, self.a, self.b)
        self.assertEqual(substring[self.a:self.b], sliced)

    def testSliceCopy(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(self.data, data[:])

    def testBoundedSliceCopy(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(substring, data[:])

    def testPositiveSlice(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(
            self.data[self.start:self.end],
            data     [self.start:self.end]
        )

    def testBoundedPositiveSlice(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[self.a:self.b],
            data     [self.a:self.b]
        )

    def testNegativeSlice(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(
            self.data[self.start-len(self.data):self.end-len(self.data)],
            data     [self.start-len(self.data):self.end-len(self.data)]
        )

    def testBoundedNegativeSlice(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[self.a-len(substring):self.b-len(substring)],
            data     [self.a-len(substring):self.b-len(substring)]
        )

    def testSliceMiss(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(
            self.data[self.end:self.start],
            data     [self.end:self.start]
        )

    def testBoundedSliceMiss(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[self.b:self.a],
            data     [self.b:self.a]
        )

    def testSliceToNowhere(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(
            self.data[:-len(self.data)],
            data     [:-len(self.data)],
        )

    def testBoundedSliceToNowhere(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[:-len(substring)],
            data     [:-len(substring)]
        )

    def testSliceFromNowhere(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(
            self.data[len(self.data):],
            data     [len(self.data):],
        )

    def testBoundedSliceFromNowhere(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[len(substring):],
            data     [len(substring):]
        )

    def testSliceOvershoot(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(
            self.data[-2*len(self.data):2*len(self.data)],
            data     [-2*len(self.data):2*len(self.data)],
        )

    def testBoundedSliceOvershoot(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[-2*len(substring):2*len(substring)],
            data     [-2*len(substring):2*len(substring)],
        )

    def testSliceWithStep(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(
            self.data[self.start:self.end:self.step],
            data     [self.start:self.end:self.step]
        )

    def testBoundedSliceWithStep(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[self.a:self.b:self.step],
            data     [self.a:self.b:self.step]
        )

    def testSliceWithNegativeStep(self):
        data = snmp.utils.subbytes(self.data)
        self.assertEqual(
            self.data[self.start:self.end:-self.step],
            data     [self.start:self.end:-self.step]
        )

    def testBoundedSliceWithNegativeStep(self):
        data = snmp.utils.subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[self.a:self.b:-self.step],
            data     [self.a:self.b:-self.step]
        )

if __name__ == "__main__":
    unittest.main()
