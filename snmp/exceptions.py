# used to indicate that a string cannot be decoded because it violates encoding rules
class EncodingError(Exception):
    pass

# used to indicate that a response violates the protocol in some way
class ProtocolError(Exception):
    pass

class Timeout(Exception):
    pass

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

STATUS_ERRORS = {
    1: TooBig,
    2: NoSuchName,
    3: BadValue,
    4: ReadOnly,
    5: GenErr,
}
