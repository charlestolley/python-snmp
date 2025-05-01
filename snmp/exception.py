class SNMPException(Exception):
    """Base class for all run-time exceptions in this library."""
    pass

class SNMPLibraryBug(AssertionError):
    """Base class for logic errors in the code of this library."""
    pass

class UnsupportedFeature(SNMPLibraryBug):
    """A failure owing to a feature that this library does not yet support."""
    pass

class IncomingMessageError(SNMPException):
    """An error indicating a received message is invalid in some way."""
    pass

class AuthentiationNotEnabled(SNMPException):
    pass

class PrivacyNotEnabled(SNMPException):
    pass

class EncodeError(SNMPException):
    pass

class ParseError(IncomingMessageError):
    pass

class BadVersion(IncomingMessageError):
    pass

class DecryptionError(IncomingMessageError):
    pass

class InvalidSignature(IncomingMessageError):
    pass

class OutsideTimeWindow(IncomingMessageError):
    pass

class ReportMessage(SNMPException):
    def __init__(self, message):
        self.message = message
