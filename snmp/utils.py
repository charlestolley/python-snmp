__all__ = ["ComparableWeakReference", "NumberGenerator", "subbytes", "typename"]

from random import randint
import weakref

class ComparableWeakReference:
    def __init__(self, obj):
        self.ref = weakref.ref(obj)

    def __call__(self):
        return self.ref()

    def __lt__(self, other):
        a = self()
        b = other()

        if a is None:
            return True
        elif b is None:
            return False
        else:
            return a < b

class NumberGenerator:
    def __init__(self, nbits, signed=True):
        half = 1 << (nbits-1)

        self.previous = 0
        self.range = half << 1
        self.step = 2 * randint(1, half) - 1
        self.wrap = self.range - 1

        if signed:
            self.wrap -= half

    def __iter__(self):
        return self

    def __next__(self):
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
