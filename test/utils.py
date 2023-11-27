__all__ = [
    "ComparableWeakRefTest", "NumberGeneratorTest",
    "SubbytesTest", "TypenameTest",
]

import unittest
from snmp.utils import *

class ComparableWeakRefTest(unittest.TestCase):
    class Counter:
        def __init__(self):
            self.count = 0

        def toInt(self):
            self.count += 1
            return self.count

    class Integer:
        def __init__(self, value):
            self.value = value

        def toInt(self):
            return self.value

    def test_if_the_referenced_object_is_still_alive_it_will_be_returned(self):
        obj = self.Integer(23)
        ref = ComparableWeakRef(obj, self.Integer.toInt)
        self.assertIs(ref(), obj)

    def test_upon_construction_it_will_call_the_provided_key_function(self):
        counter = self.Counter()
        c = ComparableWeakRef(counter, self.Counter.toInt)
        self.assertGreater(counter.count, 0)

    def test_it_will_continue_to_call_key_with_every_comparison(self):
        counter = self.Counter()
        c = ComparableWeakRef(counter, self.Counter.toInt)

        integer = self.Integer(counter.count + 1)
        i = ComparableWeakRef(integer, self.Integer.toInt)

        self.assertFalse(c < i)

    def test_it_will_continue_to_use_the_last_stored_value(self):
        counter = self.Counter()
        c = ComparableWeakRef(counter, self.Counter.toInt)
        count = counter.count
        del counter

        if c() is not None:
            self.skipTest("Deleted object was not immediately destroyed")

        equal = ComparableWeakRef(self.Integer(count), self.Integer.toInt)
        greater = ComparableWeakRef(self.Integer(count+1), self.Integer.toInt)

        self.assertFalse(c < equal)
        self.assertTrue(c < greater)

class NumberGeneratorTest(unittest.TestCase):
    def setUp(self):
        self.n = 4

    def test_length_2_to_the_n_where_each_integer_appears_exactly_once(self):
        generator = NumberGenerator(self.n)
        length = 2 ** self.n

        generated = set()
        for i in range(length):
            generated.add(next(generator))

        self.assertEqual(len(generated), length)

    def test_the_last_number_in_the_sequence_is_always_zero(self):
        generator = NumberGenerator(self.n)
        length = 2 ** self.n

        for i in range(length - 1):
            _ = next(generator)

        self.assertEqual(next(generator), 0)

    def test_the_sequence_repeats_from_the_beginning(self):
        generator = NumberGenerator(self.n)
        length = 2 ** self.n

        a = [next(generator) for i in range(length)]
        b = [next(generator) for i in range(length)]

        self.assertEqual(a, b)

    def test_generated_numbers_should_use_twos_complement_encoding(self):
        generator = NumberGenerator(self.n, signed=True)
        length = 2 ** self.n

        upper = length // 2
        lower = -upper

        for i in range(length):
            n = next(generator)
            self.assertGreaterEqual(n, lower)
            self.assertLess(n, upper)

    def test_generated_numbers_should_use_unsigned_encoding(self):
        generator = NumberGenerator(self.n, signed=False)
        length = 2 ** self.n

        upper = length
        lower = 0

        for i in range(length):
            n = next(generator)
            self.assertGreaterEqual(n, lower)
            self.assertLess(n, upper)

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
        self.assertIs(data.data, self.data)

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

    def testReplace(self):
        data = subbytes(self.data, self.start, self.stop)
        replacement = b"something something"
        result = self.data[:self.start] + replacement + self.data[self.stop:]
        self.assertEqual(data.replace(replacement), result)

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
