__all__ = ["NumberAuthorityTest", "NumberGeneratorTest"]

import unittest

from snmp.numbers import *

class NumberGeneratorTest(unittest.TestCase):
    def test_generate_2_to_the_n_unique_integers(self):
        generator = NumberGenerator(4)
        length = 2 ** 4

        generated = set()
        for i in range(length):
            generated.add(next(generator))

        self.assertEqual(len(generated), length)

    def test_the_last_number_in_the_sequence_is_always_zero(self):
        generator = NumberGenerator(4)
        length = 2 ** 4

        for i in range(length - 1):
            _ = next(generator)

        self.assertEqual(next(generator), 0)

    def test_the_sequence_repeats_from_the_beginning(self):
        generator = NumberGenerator(4)
        length = 2 ** 4

        a = [next(generator) for i in range(length)]
        b = [next(generator) for i in range(length)]

        self.assertEqual(a, b)

    def test_generate_twos_complement_integers_if_signed_is_True(self):
        generator = NumberGenerator(4, signed=True)
        length = 2 ** 4

        upper = length // 2
        lower = -upper

        for i in range(length):
            n = next(generator)
            self.assertGreaterEqual(n, lower)
            self.assertLess(n, upper)

    def test_generate_unsigned_integers_if_signed_is_False(self):
        generator = NumberGenerator(4, signed=False)
        length = 2 ** 4

        upper = length
        lower = 0

        for i in range(length):
            n = next(generator)
            self.assertGreaterEqual(n, lower)
            self.assertLess(n, upper)

class NumberAuthorityTest(unittest.TestCase):
    class TwoBitAuthority(NumberAuthority):
        @staticmethod
        def newGenerator():
            return NumberGenerator(2)

    class OneBitAuthority(NumberAuthority):
        def __init__(self, *args, **kwargs):
            self.count = 0
            self.newCount = 0
            super().__init__(*args, **kwargs)

        def __next__(self):
            self.count += 1
            return self.count % 2

        def newGenerator(self):
            self.newCount += 1
            return self

        def reset(self):
            self.count = 0
            self.newCount = 0

    class ZeroBitAuthority(NumberAuthority):
        def __init__(self, *args, **kwargs):
            self.count = 0
            super().__init__(*args, **kwargs)

        def __next__(self):
            self.count += 1
            return 1

        def newGenerator(self):
            return self

        def reset(self):
            self.count = 0

        class AllocationFailure(Exception): pass
        class DeallocationFailure(Exception): pass

    class CountingAuthority(NumberAuthority):
        def __init__(self, maxCount):
            self.maxCount = maxCount
            super().__init__()

        def newGenerator(self):
            count = 0
            while count < self.maxCount:
                count += 1
                yield count
            else:
                yield 0

        class AllocationFailure(Exception): pass
        class DeallocationFailure(Exception): pass

    def test_reserve_never_chooses_zero(self):
        authority = self.TwoBitAuthority()

        for _ in range(8):
            number = authority.reserve()
            self.assertNotEqual(number, 0)
            authority.release(number)

    def test_release_makes_the_number_available_again(self):
        authority = self.TwoBitAuthority()

        encountered = set()
        for _ in range(4):
            number = authority.reserve()
            encountered.add(number)
            authority.release(number)

        self.assertIn(authority.reserve(), encountered)

    def test_reserve_retries_allocation_attempts_times(self):
        attempts = 19
        authority = self.ZeroBitAuthority(attempts)
        _ = authority.reserve()
        authority.reset()

        try:
            _ = authority.reserve()
        except Exception:
            pass

        self.assertEqual(authority.count, attempts)

    def test_zero_doesnt_count_as_an_attempt(self):
        attempts = 25
        authority = self.OneBitAuthority(attempts)
        _ = authority.reserve()
        authority.reset()

        try:
            _ = authority.reserve()
        except Exception:
            pass

        self.assertEqual(authority.count - authority.newCount, attempts)

    def test_raise_AllocationFailure_if_reservation_fails(self):
        authority = self.ZeroBitAuthority(1)
        _ = authority.reserve()
        self.assertRaises(authority.AllocationFailure, authority.reserve)

    def test_raise_DeallocationFailure_if_the_number_is_not_reserved(self):
        authority = self.ZeroBitAuthority()
        self.assertRaises(authority.DeallocationFailure, authority.release, 1)

if __name__ == "__main__":
    unittest.main()
