__all__ = ["DummyLock", "NumberGenerator", "subbytes", "typename"]

from random import randint

class DummyLock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def acquire(self, *args, **kwargs):
        return True

    def release(self):
        pass

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
        else:
            self.data = data
            self.start = 0
            self.stop = len(data)
            data = self

        new_start = data.start if start is None else data.translate(start, True)
        new_stop  = data.stop  if stop  is None else data.translate(stop,  True)

        self.start = new_start
        self.stop  = new_stop

    def __bool__(self):
        return self.stop > self.start

    def __eq__(a, b):
        if len(a) != len(b):
            return False

        for left, right in zip(a, b):
            if left != right:
                return False

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
