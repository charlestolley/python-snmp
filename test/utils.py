__all__ = [
    "DummyLockTest", "NumberGeneratorTest", "SubbytesTest", "TypenameTest",
]

import unittest
from snmp.utils import *

class DummyLockTest(unittest.TestCase):
    def setUp(self):
        self.lock = DummyLock()

    def testContext(self):
        with self.lock as tmp:
            self.assertIs(tmp, self.lock)

    def testAcquireRelease(self):
        self.assertTrue(self.lock.acquire())
        self.lock.release()

class TypenameTest(unittest.TestCase):
    def testQualifiedClass(self):
        self.assertEqual(
            typename(self.__class__, qualified=True),
            ".".join((__name__, self.__class__.__name__))
        )

    def testQualifiedObject(self):
        self.assertEqual(
            typename(self, qualified=True),
            ".".join((__name__, self.__class__.__name__))
        )

    def testUnqualifiedClass(self):
        self.assertEqual(
            typename(self.__class__),
            self.__class__.__name__
        )

    def testUnqualifiedObject(self):
        self.assertEqual(
            typename(self),
            self.__class__.__name__
        )

class NumberGeneratorTest(unittest.TestCase):
    def setUp(self):
        self.n = 4

    def realTest(self, generator, lower, upper):
        nums = set()
        for i in generator:
            self.assertNotIn(i, nums)
            self.assertLess(i, upper)
            self.assertGreaterEqual(i, lower)
            nums.add(i)

            if i == 0:
                self.assertEqual(len(nums), upper - lower)
                break

    def testSigned(self):
        limit = 1 << (self.n - 1)
        self.realTest(NumberGenerator(self.n), -limit, limit)

    def testUnsigned(self):
        generator = NumberGenerator(self.n, signed=False)
        self.realTest(generator, 0, 1 << self.n)

class SubbytesTest(unittest.TestCase):
    def setUp(self):
        self.data = b"the quick brown fox jumps over the lazy dog"
        self.start = 4
        self.end = 25
        self.step = 3
        self.a = 6
        self.b = 15

    def testLength(self):
        data = subbytes(self.data)
        self.assertEqual(len(self.data), len(data))

    def testBoundedLength(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(len(substring), len(data))

    def testEquality(self):
        data = subbytes(self.data)
        self.assertEqual(self.data, data)

    def testBoundedEquality(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(substring, data)

    def testIterator(self):
        data = subbytes(self.data)
        for (a, b) in zip(self.data, data):
            self.assertEqual(a, b)

    def testBoundedIterator(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        for (a, b) in zip(substring, data):
            self.assertEqual(a, b)

    def testRepr(self):
        data = subbytes(self.data)
        self.assertEqual(self.data, eval(repr(data)))

    def testBoundedRepr(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(substring, eval(repr(data)))

    def testTrue(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(bool(substring), bool(data))

    def testFalse(self):
        data = subbytes(self.data, self.end, self.start)
        substring = self.data[self.end:self.start]
        self.assertEqual(bool(substring), bool(data))

    def testPositiveIntegerIndex(self):
        data = subbytes(self.data)

        i = 0
        while i < len(self.data):
            self.assertEqual(self.data[i], data[i])
            i += 1

        self.assertRaises(IndexError, data.__getitem__, i)

    def testBoundedPositiveIntegerIndex(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]

        i = 0
        while i < len(substring):
            self.assertEqual(substring[i], data[i])
            i += 1

        self.assertRaises(IndexError, data.__getitem__, i)

    def testNegativeIntegerIndex(self):
        data = subbytes(self.data)

        i = -1
        while -i <= len(self.data):
            self.assertEqual(self.data[i], data[i])
            i -= 1

        self.assertRaises(IndexError, data.__getitem__, i)

    def testBoundedNegativeIntegerIndex(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]

        i = -1
        while -i <= len(substring):
            self.assertEqual(substring[i], data[i])
            i -= 1

        self.assertRaises(IndexError, data.__getitem__, i)

    def testSetItem(self):
        data = subbytes(bytearray(self.data))
        data[self.start] += 1
        self.assertNotEqual(self.data, data)

    def testBoundedSetItem(self):
        data = subbytes(bytearray(self.data), self.start, self.end)
        substring = bytearray(self.data[self.start:self.end])
        data     [self.a] += 1
        substring[self.a] += 1
        self.assertEqual(substring, data)

    def testConsume(self):
        data = subbytes(self.data)
        byte = data.consume()
        self.assertEqual(self.data[0], byte)
        self.assertEqual(self.data[1:], data)

    def testBoundedConsume(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        byte = data.consume()
        self.assertEqual(substring[0], byte)
        self.assertEqual(substring[1:], data)

    def testEmptyConsume(self):
        data = subbytes(self.data, self.start, self.start)
        self.assertRaises(IndexError, data.consume)

    def testDereference(self):
        data = subbytes(self.data)
        byte = data.dereference()
        self.assertEqual(self.data[0], byte)
        self.assertEqual(self.data, data)

    def testBoundedDereference(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        byte = data.dereference()
        self.assertEqual(substring[0], byte)
        self.assertEqual(substring, data)

    def testEmptyDereference(self):
        data = subbytes(self.data, self.start, self.start)
        self.assertRaises(IndexError, data.dereference)

    def testPrune(self):
        data = subbytes(self.data)
        tail = data.prune(self.end)
        self.assertEqual(self.data[:self.end], data)
        self.assertEqual(self.data[self.end:], tail)

    def testSliceByConstructor(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        sliced = subbytes(data, self.a, self.b)
        self.assertEqual(substring[self.a:self.b], sliced)

    def testSliceCopy(self):
        data = subbytes(self.data)
        self.assertEqual(self.data, data[:])

    def testBoundedSliceCopy(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(substring, data[:])

    def testPositiveSlice(self):
        data = subbytes(self.data)
        self.assertEqual(
            self.data[self.start:self.end],
            data     [self.start:self.end]
        )

    def testBoundedPositiveSlice(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[self.a:self.b],
            data     [self.a:self.b]
        )

    def testNegativeSlice(self):
        data = subbytes(self.data)
        self.assertEqual(
            self.data[self.start-len(self.data):self.end-len(self.data)],
            data     [self.start-len(self.data):self.end-len(self.data)]
        )

    def testBoundedNegativeSlice(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[self.a-len(substring):self.b-len(substring)],
            data     [self.a-len(substring):self.b-len(substring)]
        )

    def testSliceMiss(self):
        data = subbytes(self.data)
        self.assertEqual(
            self.data[self.end:self.start],
            data     [self.end:self.start]
        )

    def testBoundedSliceMiss(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[self.b:self.a],
            data     [self.b:self.a]
        )

    def testSliceToNowhere(self):
        data = subbytes(self.data)
        self.assertEqual(
            self.data[:-len(self.data)],
            data     [:-len(self.data)],
        )

    def testBoundedSliceToNowhere(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[:-len(substring)],
            data     [:-len(substring)]
        )

    def testSliceFromNowhere(self):
        data = subbytes(self.data)
        self.assertEqual(
            self.data[len(self.data):],
            data     [len(self.data):],
        )

    def testBoundedSliceFromNowhere(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[len(substring):],
            data     [len(substring):]
        )

    def testSliceOvershoot(self):
        data = subbytes(self.data)
        self.assertEqual(
            self.data[-2*len(self.data):2*len(self.data)],
            data     [-2*len(self.data):2*len(self.data)],
        )

    def testBoundedSliceOvershoot(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[-2*len(substring):2*len(substring)],
            data     [-2*len(substring):2*len(substring)],
        )

    def testSliceWithStep(self):
        data = subbytes(self.data)
        self.assertEqual(
            self.data[self.start:self.end:self.step],
            data     [self.start:self.end:self.step]
        )

    def testBoundedSliceWithStep(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[self.a:self.b:self.step],
            data     [self.a:self.b:self.step]
        )

    def testSliceWithNegativeStep(self):
        data = subbytes(self.data)
        self.assertEqual(
            self.data[self.start:self.end:-self.step],
            data     [self.start:self.end:-self.step]
        )

    def testBoundedSliceWithNegativeStep(self):
        data = subbytes(self.data, self.start, self.end)
        substring = self.data[self.start:self.end]
        self.assertEqual(
            substring[self.a:self.b:-self.step],
            data     [self.a:self.b:-self.step]
        )

if __name__ == "__main__":
    unittest.main()
