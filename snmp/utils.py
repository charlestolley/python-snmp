__all__ = ["ComparableWeakRef", "NumberGenerator", "subbytes", "typename"]

from abc import ABCMeta, abstractmethod
from random import randint
import weakref

from snmp.typing import *

T = TypeVar("T")
V = TypeVar("V")    # V must support less-than comparison

@final
class ComparableWeakRef(Generic[T, V]):
    """Allow weakly-referenced objects to be used in sorted data structures.

    This class extends the behavior of the standard library's
    :class:`weakref` type by adding support for the less-than operator
    (:meth:`__lt__`). Upon construction, it will call the provided `key`
    function, with `obj` as the only argument, and the return value will be
    stored as the "comparison key". So long as the object remains alive, it
    will continue to call `key` with every comparison, and update the stored
    value. If the reference becomes invalid (i.e. the object is garbage-
    collected), then it will continue to use the last stored value for all
    future comparisons.
    """

    def __init__(self, obj: T, key: Callable[[T], V]) -> None:
        # obj could be garbage-collected as soon as this call returns, so it's
        # important to retrieve the value now, rather than initialize to None
        self._value = key(obj)

        self.key = key
        self.ref = weakref.ref(obj)

    @property
    def value(self) -> V:
        obj = self.ref()

        if obj is not None:
            self._value = self.key(obj)

        return self._value

    def __call__(self) -> Optional[T]:
        """Retrieve a reference to the wrapped object.

        If the referenced object is still alive, then it will be returned.
        Otherwise, this call will return ``None``.
        """
        return self.ref()

    def __lt__(self, other: "ComparableWeakRef[Any, V]") -> bool:
        """Compare this object to another ComparableWeakRef."""
        return cast(bool, self.value < other.value) # type: ignore[operator]

@final
class NumberGenerator:
    """Generate integers spanning a specific range.

    Given an integer size of `n` bits, an instance of this class will
    generate a sequence of length ``2^n``, where each `n`-bit integer
    appears exactly once. The first ``2^n-1`` numbers in the sequence are
    guaranteed to be non-zero; or, in other words, the last number in the
    sequence is always ``0``. After ``2^n`` iterations, the sequence repeats
    from the beginning.

    The `signed` argument determines whether the generated numbers should
    use two's-complement encoding (i.e. cover the range ``-(2^(n-1))`` to
    ``2^(n-1)-1``, inclusive), or unsigned encoding (``0`` to ``2^n-1``).
    """

    def __init__(self, n: int, signed: bool = True) -> None:
        half = 1 << (n-1)

        self.previous = 0
        self.range = half << 1
        self.step = 2 * randint(1, half) - 1
        self.wrap = self.range - 1

        if signed:
            self.wrap -= half

    def __iter__(self) -> Iterator[int]:
        return self

    def __next__(self) -> int:
        """Give the next number in the sequence."""
        self.previous += self.step

        if self.previous > self.wrap:
            self.previous -= self.range

        return self.previous

@final
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

        The :attr:`data` attribute provides a reference to the underlying
        bytes-like object. If the `data` argument to the constructor is an
        instance of :class:`subbytes`, it will be unwrapped so that this
        attribute always references a bytes-like object directly.
    """

    def __init__(self,
        data: Union[bytes, "subbytes"],
        start: Optional[int] = None,
        stop: Optional[int] = None,
    ) -> None:
        self.data: bytes
        if isinstance(data, subbytes):
            self.data = data.data
            base = data
        else:
            self.data = data
            self.start = 0
            self.stop = len(data)
            base = self

        newstart = base.start if start is None else base.translate(start, True)
        newstop  = base.stop  if stop  is None else base.translate(stop,  True)

        self.start = newstart
        self.stop  = newstop

    def __bool__(self) -> bool:
        """Indicate that the sequence is non-empty."""
        return self.stop > self.start

    def __eq__(self, other: Any) -> bool:
        """Compare two sequences of bytes for equality."""
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

    @overload
    def __getitem__(self, key: int) -> int:
        ...

    @overload
    def __getitem__(self, key: slice) -> bytes:
        ...

    def __getitem__(self, key: Union[int, slice]) -> Union[int, bytes]:
        """Retrieve an individual byte or copy a sub-sequence."""
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

    def __iter__(self) -> Iterator[int]:
        """Produce an iterator for this sequence."""
        for index in range(self.start, self.stop):
            yield self.data[index]

    def __len__(self) -> int:
        """Query the length of the sequence."""
        return self.stop - self.start

    def __repr__(self) -> str:
        """Provide an :func:`eval`-able representation of this object."""
        args = [repr(self.data)]

        if self.start:
            args.append(f"start={self.start}")

        if self.stop < len(self.data):
            args.append(f"stop={self.stop}")

        return f"{typename(self)}({', '.join(args)})"

    def translate(self, index: int, clamp: bool = False) -> int:
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

    def consume(self) -> int:
        """Pop a byte off the front of the sequence.

        This function returns the first byte of the current sequence, advancing
        the start index relative to :attr:`data` by one. If the sequence is
        empty, then an :exc:`IndexError` will be raised.
        """
        byte = self.dereference()
        self.start += 1
        return byte

    def dereference(self) -> int:
        """Retrieve the first byte of the sequence.

        If the sequence is empty, an :exc:`IndexError` will be raised
        """
        return self[0]

    def prune(self, length: int) -> "subbytes":
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

    def replace(self, replacement: bytes) -> bytes:
        """Substitute the given string in place of the current sequence

        This method produces a copy of the wrapped object, in which the
        current sequence has been replaced with the contents of the
        `replacement` argument.
        """
        return self.data[:self.start] + replacement + self.data[self.stop:]

def typename(cls: Any, qualified: bool = False) -> str:
    """Query an object to determine its type.

    :param cls:
        If ``cls`` is a class, this function will return its name.  If
        ``cls`` is an object, this function will return the name of the
        object's class.
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
        return cast(type, cls).__name__
