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
        self.stop = 25
        self.step = 3
        self.a = 6
        self.b = 15

    def testNotEqual(self):
        data = subbytes(self.data)
        self.assertNotEqual(data, self.data[1:])

    def testConstructorSignature(self):
        data = subbytes(self.data, start=self.start, stop=self.stop)

    def testBasicConstruction(self):
        data = subbytes(self.data)
        self.assertEqual(data, self.data)

    def testBoundedConstruction(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        self.assertEqual(data, substring)

    def testWrappingConstruction(self):
        wrapped = subbytes(self.data, self.start, self.stop)
        data = subbytes(wrapped, self.a, self.b)
        substring = self.data[self.start:self.stop][self.a:self.b]
        self.assertEqual(data, substring)

    def testFalse(self):
        self.assertFalse(subbytes(self.data, self.start, self.start))

    def testTrue(self):
        self.assertTrue(subbytes(self.data, self.start, self.start+1))

    def testIterator(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        for (a, b) in zip(data, substring):
            self.assertEqual(a, b)

    def testLength(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        self.assertEqual(len(substring), len(data))

    def testRepr(self):
        data = subbytes(self.data, self.start, self.stop)
        copy = eval(repr(data))

        self.assertEqual(type(copy), type(data))
        self.assertEqual(copy, data)

    def testGetItemPositiveIntegerIndex(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]

        for i in range(len(data)):
            self.assertEqual(data[i], substring[i])

        self.assertRaises(IndexError, data.__getitem__, len(data))

    def testGetItemNegativeIntegerIndex(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]

        for i in range(-len(data), 0):
            self.assertEqual(data[i], substring[i])

    def testGetItemFullSlice(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        self.assertEqual(data[:], substring)

    def testGetItemPositiveSlice(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        self.assertEqual(data[self.a:self.b], substring[self.a:self.b])

    def testGetItemNegativeSlice(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        a = self.a - len(data)
        b = self.b - len(data)
        self.assertEqual(data[a:b], substring[a:b])

    def testGetItemSliceMiss(self):
        data = subbytes(self.data, self.start, self.stop)
        self.assertEqual(data[self.b:self.a], b"")

    def testGetItemSliceOvershoot(self):
        data = subbytes(self.data, self.start, self.stop)
        self.assertEqual(data[-2*len(data):2*len(data)], data)

    def testGetItemSliceWithStep(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        self.assertEqual(
            data     [self.a:self.b:self.step],
            substring[self.a:self.b:self.step]
        )

    def testGetItemSliceWithNegativeStep(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        self.assertEqual(
            data     [self.a:self.b:-self.step],
            substring[self.a:self.b:-self.step]
        )

    def testBoundedConsume(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        byte = data.consume()
        self.assertEqual(byte, substring[0])
        self.assertEqual(data, substring[1:])

    def testEmptyConsume(self):
        data = subbytes(self.data, self.start, self.start)
        self.assertRaises(IndexError, data.consume)

    def testDereference(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        byte = data.dereference()
        self.assertEqual(byte, substring[0])
        self.assertEqual(data, substring)

    def testEmptyDereference(self):
        data = subbytes(self.data, self.start, self.start)
        self.assertRaises(IndexError, data.dereference)

    def testPrune(self):
        data = subbytes(self.data, self.start)
        tail = data.prune(self.stop - self.start)
        self.assertEqual(data, self.data[self.start:self.stop])
        self.assertEqual(tail, self.data[self.stop:])

if __name__ == "__main__":
    unittest.main()
