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
        """Get the next number in the sequence."""
        self.previous += self.step

        if self.previous > self.wrap:
            self.previous -= self.range

        return self.previous

class subbytes:
    """Operate on a slice of a bytes-like object without copying any data.

    This class represents a sequence of bytes, similarly to how data is
    represented in a bytes-like object. Unlike a bytes-like object, however,
    a :class:`subbytes` object does not store this data in a memory block of
    its own. It holds a reference to a real bytes-like object, and acts on a
    sub-sequence of that object's data, as if it had been copied into a
    separate bytes-like object.  The arguments to the constructor mirror the
    arguments to the built-in :func:`slice` function, so that
    ``subbytes(data, start, stop)`` represents the same sequence of bytes as
    ``data[start:stop]``.

    .. attribute:: data

        The :attr:`data` attribute provides a reference to the full sequence
        of bytes. If the `data` argument to the constructor is an instance
        of :class:`subbytes`, it will be unwrapped so that the data
        attribute always references a bytes-like object directly.
    """

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
        """Indicate that the sequence is non-empty"""
        return self.stop > self.start

    def __eq__(self, other):
        """Compare two sequences of bytes for equality"""
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

    def __getitem__(self, key):
        """Retrieve an individual byte or copy a sub-sequence"""
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

    def __iter__(self):
        """Produce an iterator for this sequence"""
        for index in range(self.start, self.stop):
            yield self.data[index]

    def __len__(self):
        """Query the length of the sequence"""
        return self.stop - self.start

    def __repr__(self):
        """Provide an :func:`eval`-able representation of this object"""
        args = [repr(self.data)]

        if self.start:
            args.append(f"start={self.start}")

        if self.stop < len(self.data):
            args.append(f"stop={self.stop}")

        return f"{typename(self)}({', '.join(args)})"

    def translate(self, index, clamp=False):
        """Convert an index of self into an index of :attr:`data`.

        This method accepts an integral `index` of any value and translates it
        into a meaningful index of :attr:`data`. If ``-len(self)`` <= `index` <
        ``len(self)``, then the result is guaranteed to be a valid index
        (meaning it will not cause an :exc:`IndexError`). If `index` <
        ``-len(self)`` and `clamp` is ``True``, then this method will return
        the index of the start of this sequence, which is only guaranteed to be
        valid if the sequence is non-empty, and may or may not be valid if the
        sequence is empty. If ``len(self)`` <= `index` and `clamp` is ``True``,
        then this method will return the stop index, which is the index just
        beyond the end of the sequence. The stop index may or may not be valid,
        regardless of the length of the sequence, but it is guaranteed to match
        the start index if the sequence is empty. Under any other scenario
        (i.e. `index` is out of range and `clamp` is ``False``), the result is
        guaranteed to be an invalid index.

        :meta private:
        """
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

    def consume(self):
        """Pop a byte off the front of the sequence.

        This function returns the first byte of the current sequence, advancing
        the start index relative to :attr:`data` by one. If the sequence is
        empty, then an :exc:`IndexError` will be raised.
        """
        byte = self.dereference()
        self.start += 1
        return byte

    def dereference(self):
        """Retrieve the first byte of the sequence.

        If the sequence is empty, an :exc:`IndexError` will be raised
        """
        return self[0]

    def prune(self, length):
        """Cut the sequence down to length.

        This method effectively splits the current sequence at index `length`,
        truncating it to that length, and returning a new :class:`subbytes`
        object that references the portion that was cut off of the end. If
        the `length` argument exceeds the length of the sequence, then the
        current object will remain unchanged and the returned :class:`subbytes`
        object will contain an empty sequence.
        """
        removed = subbytes(self, length)
        self.stop = removed.start
        return removed

def typename(cls, qualified=False):
    """Query an object to determine its type.

    :param cls:
        If ``cls`` is a class, this function will return the name of that
        class. If ``cls`` is an object, this function will return the name
        of the object's class.
    :param bool qualified:
        Indicate whether to return the fully-qualified name, which includes
        the module path, as well as the names of any enclosing classes (for
        inner classes).
    """
    if not isinstance(cls, type):
        cls = type(cls)

    if qualified:
        return ".".join((cls.__module__, cls.__qualname__))
    else:
        return cls.__name__
