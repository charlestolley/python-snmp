__all__ = ["ComparableWeakRef", "NumberGenerator", "subbytes", "typename"]

from random import randint
import weakref

class ComparableWeakRef:
    """Allow weakly-referenced objects to be used in sorted data structures.

    When weakly-referenced objects are stored in a sorted data structure,
    such as a binary heap, the unexpected replacement of an object with
    ``None`` can violate the structure's invariants, causing the structure
    to behave unpredictably. This class provides a proxy :meth:`__lt__`
    method that enables proper sorting even after the referenced object has
    been garbage-collected.
    """

    def __init__(self, obj, key):
        """
        :param obj: Any object.
        :param key:
            This argument mimics the ``key`` argument to the built-in
            :func:`sorted` function; that is, a call to ``key(obj)`` returns a
            value that can be used to compare ``obj`` to another object of the
            same type.
        """
        # obj could be garbage-collected as soon as this call returns, so it's
        # important to retrieve the value now, rather than initialize to None
        self._value = key(obj)

        self.key = key
        self.ref = weakref.ref(obj)

    @property
    def value(self):
        obj = self.ref()
        if obj is not None:
            self._value = self.key(obj)
        return self._value

    def __call__(self):
        """Retrieve a reference to the wrapped object.

        If the referenced object is still alive, then it will be returned.
        Otherwise, this call will return ``None``.
        """
        return self.ref()

    def __lt__(self, other):
        """Compare this object to another ComparableWeakRef."""
        return self.value < other.value

class NumberGenerator:
    """Generate integers spanning a specific range.

    Given an integer size of ``n`` bits, an instance of this class will
    generate a sequence of length ``2^n``, where each ``n``-bit integer
    appears exactly once. Additionally, the first ``2^n-1`` numbers in the
    sequence are guaranteed to be non-zero; or, in other words, the last
    number in the sequence is always ``0``. After ``2^n`` iterations, the
    sequence repeats from the beginning.
    """

    def __init__(self, n, signed=True):
        """
        :param int n: The size of the generated integers, in bits.
        :param bool signed:
            Indicates whether to use two's complement or unsigned numbers.
        """
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
        """Return the next number in the sequence"""
        self.previous += self.step

        if self.previous > self.wrap:
            self.previous -= self.range

        return self.previous

class subbytes:
    def __init__(self, data, start=None, stop=None):
        if isinstance(data, subbytes):
            self.data = data.data
            base = data
        else:
            self.data = data
            self.start = 0
            self.stop = len(data)
            base = self

        new_start = base.start if start is None else base.translate(start, True)
        new_stop  = base.stop  if stop  is None else base.translate(stop,  True)

        self.start = new_start
        self.stop  = new_stop

    def __bool__(self):
        return self.stop > self.start

    def __eq__(self, other):
        try:
            # TypeError if other is not Sized
            if len(self) != len(other):
                return False

            # TypeError if other is not Iterable
            for left, right in zip(self, other):
                if left != right:
                    return False
        except TypeError:
            return NotImplemented

        return True

    def __iter__(self):
        for index in range(self.start, self.stop):
            yield self.data[index]

    def __len__(self):
        return self.stop - self.start

    def __repr__(self):
        args = [repr(self.data)]

        if self.start:
            args.append(f"start={self.start}")

        if self.stop < len(self.data):
            args.append(f"stop={self.stop}")

        return f"{typename(self)}({', '.join(args)})"

    def translate(self, index, clamp=False):
        if index < 0:
            index += self.stop
            if index < self.start:
                if clamp:
                    return self.start
                else:
                    return len(self.data)
            else:
                return index
        else:
            index += self.start
            if index >= self.stop:
                if clamp:
                    return self.stop
                else:
                    return len(self.data)
            else:
                return index

    def __getitem__(self, key):
        if isinstance(key, int):
            key = self.translate(key)
        elif isinstance(key, slice):
            start, stop = key.start, key.stop

            key = slice(
                self.start if start is None else self.translate(start, True),
                self.stop  if stop  is None else self.translate(stop, True),
                key.step
            )

        return self.data[key]

    def consume(self):
        byte = self.dereference()
        self.start += 1
        return byte

    def dereference(self):
        return self[0]

    def prune(self, length):
        removed = subbytes(self, length)
        self.stop = removed.start
        return removed

def typename(cls, qualified=False):
    if not isinstance(cls, type):
        cls = type(cls)

    if qualified:
        return ".".join((cls.__module__, cls.__qualname__))
    else:
        return cls.__name__
