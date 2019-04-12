# used to indicate that a string cannot be decoded because it violates encoding rules
class EncodingError(Exception):
    pass

# used to indicate that a response violates the protocol in some way
class ProtocolError(Exception):
    pass

class Timeout(Exception):
    pass
