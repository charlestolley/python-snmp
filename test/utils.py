__all__ = [
    "ComparableWeakRefTest", "NumberGeneratorTest",
    "ResultWhileAliveTest", "SubbytesTest", "TypenameTest",
]

import unittest
import weakref

from snmp.utils import *
from snmp.utils import ResultWhileAlive

class ResultWhileAliveTest(unittest.TestCase):
    class Counter:
        def __init__(self, value):
            self.value = value

        def advance(self, step=1):
            self.value += step

        def intValue(self):
            return self.value

    def test_capture_the_value_upon_construction(self):
        counter = self.Counter(19)
        ref = weakref.ref(counter)
        result = ResultWhileAlive(self.Counter.intValue, counter)
        del counter

        if ref() is not None:
            self.skipTest("Deleted object was not immediately destroyed")

        self.assertEqual(result.value, 19)

    def test_stored_value_is_only_updated_by_a_call_to_value(self):
        counter = self.Counter(19)
        ref = weakref.ref(counter)
        result = ResultWhileAlive(self.Counter.intValue, counter)
        counter.advance()
        del counter

        if ref() is not None:
            self.skipTest("Deleted object was not immediately destroyed")

        self.assertEqual(result.value, 19)

    def test_call_key_while_obj_remains_alive(self):
        counter = self.Counter(19)
        result = ResultWhileAlive(self.Counter.intValue, counter)
        counter.advance(3)
        self.assertEqual(result.value, 22)

        counter.advance(6)
        _ = result.value
        del counter
        self.assertEqual(result.value, 28)

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

    # Equality tests

    def test_equal_when_byte_sequence_matches(self):
        data = subbytes(self.data)
        self.assertEqual(data, self.data)
        self.assertEqual(data, list(self.data))

    def test_not_equal_if_too_short(self):
        data = subbytes(self.data)
        self.assertNotEqual(data, self.data[:-1])

    def test_not_equal_if_too_long(self):
        data = subbytes(self.data)
        self.assertNotEqual(data, self.data + b"\0")

    def test_not_equal_if_bytes_differ(self):
        data = subbytes(self.data)
        modified = bytearray(self.data)
        modified[0] += 1
        self.assertNotEqual(data, modified)

    def test_not_equal_to_incompatible_object(self):
        data = subbytes(self.data)
        self.assertNotEqual(data, 27.9)
        self.assertNotEqual(data, self.__class__)

    # Constructor tests

    def test_constructor_args_are_named_start_and_stop(self):
        a = subbytes(self.data, start=self.start, stop=self.stop)
        b = subbytes(self.data, self.start, self.stop)
        self.assertEqual(a, b)

    def test_slice_with_valid_nonnegative_indices_is_equal(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        self.assertEqual(data, substring)

    def test_slice_with_valid_negative_indices_is_equal(self):
        start = self.start - len(self.data)
        stop = self.stop - len(self.data)

        data = subbytes(self.data, start, stop)
        substring = self.data[start:stop]

        self.assertEqual(data, substring)

    def test_subbytes_of_subbytes_equals_slice_of_slice(self):
        wrapped = subbytes(self.data, self.start, self.stop)
        data = subbytes(wrapped, self.a, self.b)
        substring = self.data[self.start:self.stop][self.a:self.b]
        self.assertEqual(data, substring)

    def test_the_data_attribute_will_be_unwrapped(self):
        wrapped = subbytes(self.data)
        data = subbytes(wrapped)
        self.assertNotIsInstance(data.data, subbytes)

    # Misc. double-underscore methods tests

    def test_empty_sequence_evaluates_to_False(self):
        self.assertFalse(subbytes(self.data, self.start, self.start))

    def test_nonempty_sequence_evaluates_to_True(self):
        self.assertTrue(subbytes(self.data, self.start, self.start+1))

    def test_iteration_yields_the_same_bytes_as_iterating_over_a_slice(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]

        for a, b in zip(data, substring):
            self.assertEqual(a, b)

    def test_len_matches_the_length_of_a_slice(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        self.assertEqual(len(data), len(substring))

    def test_the_result_of_eval_repr_is_equal_to_the_original(self):
        data = subbytes(self.data, self.start, self.stop)
        copy = eval(repr(data))

        self.assertEqual(type(copy), type(data))
        self.assertEqual(copy, data)

    def test_repr_uses_keyword_argument_names(self):
        data = subbytes(self.data, stop=self.stop)
        copy = eval(repr(data))

        self.assertEqual(copy, data)

    # Indexing tests

    def test_getitem_with_a_valid_int_returns_the_byte_at_that_index(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]

        for i in range(-len(data), len(data)):
            self.assertEqual(data[i], substring[i])

    def test_getitem_with_invalid_int_raises_IndexError(self):
        data = subbytes(self.data, self.start, self.stop)
        self.assertRaises(IndexError, data.__getitem__, len(data))
        self.assertRaises(IndexError, data.__getitem__, -len(data) - 1)

    # Slice tests

    def test_slice_with_no_arguments_returns_a_copy_of_data(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        copy = data[:]

        self.assertEqual(copy, substring)
        self.assertEqual(type(copy), type(substring))

    def test_slice_in_bounds_without_step_equals_slice_of_slice_of_data(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]

        for a in (self.a, self.a - len(data)):
            for b in (self.b, self.b - len(data)):
                self.assertEqual(data[a:b], substring[a:b])

    def test_slice_in_bounds_with_step_equals_slice_of_slice_of_data(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]

        self.assertEqual(
            data     [self.a:self.b:self.step],
            substring[self.a:self.b:self.step]
        )

        self.assertEqual(
            data     [self.a:self.b:-self.step],
            substring[self.a:self.b:-self.step]
        )

    def test_slice_with_non_overlapping_indices_is_empty(self):
        data = subbytes(self.data, self.start, self.stop)
        self.assertEqual(len(data[self.b:self.a]), 0)

    def test_slice_indices_clamp_to_start_and_stop(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]

        self.assertEqual(data[:len(data)+4], substring)
        self.assertEqual(data[-len(data)-9:], substring)
        self.assertEqual(data[-2*len(data):2*len(data)], substring)

    # dereference() tests

    def test_dereference_returns_the_first_byte_without_side_effect(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        byte = data.dereference()
        self.assertEqual(byte, substring[0])
        byte = data.dereference()
        self.assertEqual(byte, substring[0])
        self.assertEqual(data, substring)

    def test_dereference_raises_IndexError_when_the_sequence_is_empty(self):
        data = subbytes(self.data, self.start, self.start)
        self.assertRaises(IndexError, data.dereference)

    # pop_front() tests

    def test_pop_front_returns_the_first_byte_and_remainder_if_non_empty(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        byte, data = data.pop_front()
        self.assertEqual(byte, substring[0])
        self.assertEqual(data, substring[1:])

    def test_pop_front_raises_IndexError_if_empty(self):
        data = subbytes(self.data, self.start, self.start)
        self.assertRaises(IndexError, data.pop_front)

    def test_pop_front_does_not_modify_the_current_object(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        byte, _ = data.pop_front()
        self.assertEqual(data, substring)

    # replace() tests

    def test_replace_produces_a_copy_with_the_current_sequence_replaced(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        replacement = b"something something"

        prefix = self.data[:self.start]
        suffix = self.data[self.stop:]
        result = prefix + replacement + suffix

        self.assertEqual(data.replace(replacement), result)
        self.assertEqual(data, substring)

    # split() tests

    def test_split_returns_two_new_objects(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        first, second = data.split(self.a)

        self.assertIsNot(first, data)
        self.assertIsNot(second, data)

    def test_split_does_not_modify_the_current_object(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        first, second = data.split(self.a)

        self.assertEqual(data, substring)

    def test_split_first_object_references_everything_before_index(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        first, _ = data.split(self.a)

        self.assertEqual(first, substring[:self.a])

    def test_split_second_object_references_everything_from_index(self):
        data = subbytes(self.data, self.start, self.stop)
        substring = self.data[self.start:self.stop]
        _, second = data.split(self.a)

        self.assertEqual(second, substring[self.a:])

class TypenameTest(unittest.TestCase):
    class Inner:
        pass

    def test_return_the_fully_qualified_class_name(self):
        result = typename(self.Inner, qualified=True)
        self.assertEqual(result, __name__ + ".TypenameTest.Inner")

    def test_return_the_fully_qualified_name_of_the_objects_class(self):
        result = typename(self.Inner(), qualified=True)
        self.assertEqual(result, __name__ + ".TypenameTest.Inner")

    def test_return_the_unqualified_class_name(self):
        self.assertEqual(typename(self.Inner), "Inner")

    def test_return_the_unqualified_name_of_the_objects_class(self):
        self.assertEqual(typename(self.Inner()), "Inner")

if __name__ == "__main__":
    unittest.main()
