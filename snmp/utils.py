__all__ = ["forbidKeywordArgument", "subbytes", "typename"]

import os

class subbytes:
    """Operate on a slice of a bytes-like object without copying any data.

    This class represents a sequence of bytes, similarly to how data is
    represented in a bytes-like object. Unlike a bytes-like object, however,
    a subbytes object does not store this data in a memory block of its own.
    It holds a reference to a real bytes-like object, and acts on a
    sub-sequence of that object's data, as if it had been copied into a
    separate bytes-like object. The arguments to the constructor mirror the
    arguments to the built-in slice() function, (without the step parameter)
    so that subbytes(data, start, stop) represents the same sequence of bytes
    as data[start:stop].

    .. attribute:: data

        The data attribute provides a reference to the underlying bytes-like
        object. If the data argument to the constructor is an instance of
        subbytes, it will be unwrapped so that this attribute always references
        a bytes-like object directly.
    """

    def __init__(self, data, start = None, stop = None):
        self._data: bytes
        if isinstance(data, subbytes):
            self._data = data.data
            base = data
        else:
            self._data = data
            self._start = 0
            self._stop = len(data)
            base = self

        newstart = base.start if start is None else base.translate(start, True)
        newstop  = base.stop  if stop  is None else base.translate(stop,  True)

        self._start = newstart
        self._stop  = newstop

    @property
    def data(self):
        return self._data

    @property
    def start(self):
        return self._start

    @property
    def stop(self):
        return self._stop

    def __bool__(self):
        """Indicate that the sequence is non-empty."""
        return self.stop > self.start

    def __eq__(self, other):
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

    def __getitem__(self, key):
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

    def __iter__(self):
        """Produce an iterator for this sequence."""
        for index in range(self.start, self.stop):
            yield self.data[index]

    def __len__(self):
        """Query the length of the sequence."""
        return self.stop - self.start

    @staticmethod
    def _format(data, step, indent="", sep=""):
        lines = []
        start = 0

        while start < len(data):
            stop = start + step
            block = data[start:stop]
            line = sep.join(f"{b:02x}" for b in block)
            lines.append(indent + line)
            start = stop

        return os.linesep.join(lines)

    def __str__(self):
        sections = []

        if self.start > 0:
            prefix = self.data[:self.start]
            sections.append(self._format(prefix, 40))

        indent = 4 * " "
        if self.start < self.stop:
            data = self.data[self.start:self.stop]
            sections.append(self._format(data, 24, indent=indent, sep=" "))
        else:
            sections.append(indent + "(empty)")

        if self.stop < len(self.data):
            suffix = self.data[self.stop:]
            sections.append(self._format(suffix, 40))

        separator = 2 * os.linesep
        body = separator.join(sections)

        header = 32 * "=" + " begin subbytes " + 32 * "="
        footer = 33 * "=" +  " end subbytes "  + 33 * "="
        return os.linesep.join((header, body, footer))

    def __repr__(self):
        """Provide an eval()-able representation of this object."""
        args = [repr(self.data)]

        if self.start:
            args.append(f"start={self.start}")

        if self.stop < len(self.data):
            args.append(f"stop={self.stop}")

        return f"{typename(self)}({', '.join(args)})"

    def translate(self, index, clamp = False):
        """Convert an index of self into an index of self.data.

        This method accepts an integral index of any value and translates it
        into a meaningful index of self.data. If -len(self) <= index <
        len(self), then the result is guaranteed to be a valid index (meaning
        it will not cause an IndexError). If index < -len(self) and clamp is
        True, then this method will return the index of the start of this
        sequence, which is only guaranteed to be valid if the sequence is
        non-empty, and may or may not be valid if the sequence is empty. If
        len(self) <= index and clamp is True, then this method will return the
        stop index, which is the index just beyond the end of the sequence. The
        stop index may or may not be valid, regardless of the length of the
        sequence, but it is guaranteed to match the start index if the sequence
        is empty. Under any other scenario (i.e. index is out of range and
        clamp is False), the result is guaranteed to be an invalid index.

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

    def dereference(self):
        """Retrieve the first byte of the sequence.

        If the sequence is empty, an IndexError will be raised.
        """
        return self[0]

    def pop_front(self):
        """Shortcut for split(1) followed by dereference().

        This method returns a tuple containing, first, the int value of the
        first byte, and second, a new subbytes object referencing the same
        underlying sequence, starting from index 1.

        If the sequence is empty, this method will raise an IndexError.
        """
        a, b = self.split(1)
        return a.dereference(), b

    def replace(self, replacement):
        """Substitute the given string in place of the current sequence

        This method produces a copy of the wrapped object, in which the
        current sequence has been replaced with the contents of the
        replacement argument.
        """
        return self.data[:self.start] + replacement + self.data[self.stop:]

    def split(self, index):
        """Split the sequence at the given index.

        Return two new objects, the first referencing the portion of the
        sequence  starting at the beginning of the current sequence and ending
        just before index, and the second referencing the portion beginning
        at index and ending at the end of the current sequence.
        """
        return subbytes(self, stop=index), subbytes(self, start=index)

def forbidKeywordArgument(funcname, keyword, kwargs):
    if keyword in kwargs:
        errmsg = f"{funcname}() got an unexpected keyword argument {keyword!r}"
        raise TypeError(errmsg)

def typename(cls, qualified = False):
    """Query an object to determine its type.

    :param cls:
        If cls is a class, this function will return its name. If cls is an
        object, this function will return the name of the object's class.
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
