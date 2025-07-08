__all__ = ["NumberAuthority", "NumberGenerator"]

from random import randint

class NumberGenerator:
    """Generate integers spanning a specific range.

    Given an integer size of n bits, an instance of this class will generate
    a sequence of length 2^n, where each n-bit integer appears exactly once.
    The first 2^n-1 numbers in the sequence are guaranteed to be non-zero; or,
    in other words, the last number in the sequence is always 0. After 2^n
    iterations, the sequence repeats from the beginning.

    The signed argument determines whether the generated numbers should use
    two's-complement encoding (i.e. cover the range -(2^(n-1)) to 2^(n-1)-1,
    inclusive), or unsigned encoding (0 to 2^n-1).
    """

    def __init__(self, n, signed = True):
        half = 1 << (n-1)

        self.previous = 0
        self.range = half << 1
        self.step = 2 * randint(1, half) - 1
        self.wrap = self.range - 1

        if signed:
            self.wrap -= half

    def __iter__(self):
        return self

    def __next__(self):
        """Return the next number in the sequence."""
        self.previous += self.step

        if self.previous > self.wrap:
            self.previous -= self.range

        return self.previous

class NumberAuthority:
    def __init__(self, attempts=10):
        self.attempts = attempts
        self.generator = self.newGenerator()
        self.reserved = set()

    def release(self, number):
        try:
            self.reserved.remove(number)
        except KeyError as err:
            raise self.DeallocationFailure(number) from err

    def reserve(self):
        for attempt in range(self.attempts):
            number = next(self.generator)

            if number == 0:
                self.generator = self.newGenerator()
                number = next(self.generator)

            if number not in self.reserved:
                self.reserved.add(number)
                return number

        raise self.AllocationFailure(self.attempts)
