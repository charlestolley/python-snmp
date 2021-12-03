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
                    return len(data)
            else:
                return index
        else:
            index += self.start
            if index >= self.end:
                if clamp:
                    return self.end
                else:
                    return len(data)
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
