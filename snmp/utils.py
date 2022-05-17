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
    def __init__(self, data, start=0, end=None):
        if isinstance(data, subbytes):
            if end is None:
                end = data.end

            self.data  = data.data
            self.start = min(data.start + start, data.end)
            self.end   = min(data.start + end,   data.end)
        else:
            if end is None:
                end = len(data)

            self.data  = data
            self.start = min(start, len(data))
            self.end   = min(end,   len(data))

    def __eq__(a, b):
        if len(a) != len(b):
            return False

        for chars in zip(a, b):
            if chars[0] != chars[1]:
                return False

        return True

    def __iter__(self):
        for index in range(self.start, self.end):
            yield self.data[index]

    def __len__(self):
        return self.end - self.start

    def __bool__(self):
        return self.end > self.start

    def __repr__(self):
        return repr(self[:])

    def translate(self, index, clamp=False):
        if index < 0:
            index += self.end
            if index < self.start:
                if clamp:
                    return self.start
                else:
                    return len(self.data)
            else:
                return index
        else:
            index += self.start
            if index >= self.end:
                if clamp:
                    return self.end
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
                self.end   if stop  is None else self.translate(stop, True),
                key.step
            )

        return self.data[key]

    def __setitem__(self, key, value):
        if isinstance(key, int):
            key = self.translate(key)

        self.data[key] = value

    def consume(self):
        byte = self.dereference()
        self.start += 1
        return byte

    def dereference(self):
        return self[0]

    def prune(self, length):
        removed = subbytes(self, length)
        self.end = removed.start
        return removed

def typename(cls, qualified=False):
    if not isinstance(cls, type):
        cls = type(cls)

    if qualified:
        return ".".join((cls.__module__, cls.__qualname__))
    else:
        return cls.__name__
