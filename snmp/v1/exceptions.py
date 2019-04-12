class StatusError(Exception):
    pass

class TooBig(StatusError):
    pass

class NoSuchName(StatusError):
    pass

class BadValue(StatusError):
    pass

class ReadOnly(StatusError):
    pass

class GenErr(StatusError):
    pass
