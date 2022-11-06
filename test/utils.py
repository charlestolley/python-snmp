__all__ = [
    "ComparableWeakRefTest", "NumberGeneratorTest",
    "SubbytesTest", "TypenameTest",
]

import unittest
from snmp.utils import *

class ComparableWeakRefTest(unittest.TestCase):
    class Integer:
        def __init__(self, value):
            self.value = value

        def toInt(self):
            return self.value

    def testCall(self):
        obj = self.Integer(23)
        ref = ComparableWeakRef(obj, self.Integer.toInt)
        self.assertIs(ref(), obj)

    def testComparison(self):
        a = self.Integer(5)
        b = self.Integer(10)
        aref = ComparableWeakRef(a, self.Integer.toInt)
        bref = ComparableWeakRef(b, self.Integer.toInt)

        self.assertLess(aref, bref)
        self.assertFalse(bref < aref)

    def testPersistence(self):
        i = self.Integer(3)
        dead = ComparableWeakRef(self.Integer(4), self.Integer.toInt)
        alive = ComparableWeakRef(i, self.Integer.toInt)

        if dead() is not None:
            reason = "Ephemeral object was not immediately garbage-collected"
            self.skipTest(reason)

        self.assertLess(alive, dead)
        self.assertFalse(dead < alive)

class NumberGeneratorTest(unittest.TestCase):
    def setUp(self):
        self.n = 4

    def realTest(self, generator, lower, upper):
        nums = set()
        allNums = set(range(lower, upper))
        for _ in allNums:
            i = next(generator)
            nums.add(i)

        self.assertEqual(nums, allNums)
        self.assertEqual(i, 0)

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

    def testReprKeyword(self):
        data = subbytes(self.data, stop=self.stop)
        copy = eval(repr(data))

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

    def testLongPrune(self):
        data = subbytes(self.data, self.start, self.stop)
        tail = data.prune(2 * len(data))
        self.assertEqual(data, self.data[self.start:self.stop])
        self.assertEqual(tail, b"")

class TypenameTest(unittest.TestCase):
    class Inner:
        pass

    def checkQualifiedName(self, qualname):
        self.assertTrue(qualname.startswith(__name__))
        self.assertEqual(qualname[len(__name__)], ".")

        # drop the module path
        qualname = qualname[len(__name__)+1:]
        self.assertIs(eval(qualname), self.Inner)

    def checkUnqualifiedName(self, name):
        self.assertEqual(name, "Inner")

    def testQualifiedClass(self):
        self.checkQualifiedName(typename(self.Inner, qualified=True))

    def testQualifiedObject(self):
        self.checkQualifiedName(typename(self.Inner(), qualified=True))

    def testUnqualifiedClass(self):
        self.checkUnqualifiedName(typename(self.Inner))

    def testUnqualifiedObject(self):
        self.checkUnqualifiedName(typename(self.Inner()))

if __name__ == "__main__":
    unittest.main()
