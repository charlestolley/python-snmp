__all__ = [
    "SNMPException",
    "SNMPLibraryBug",
    "UnsupportedFeature",
    "IncomingMessageError",
    "IncomingMessageErrorWithPointer",
    "AuthenticationNotEnabled",
    "PrivacyNotEnabled",
    "EncodeError",
    "InvalidSignature",
    "UsmUnsupportedSecLevel",
    "UsmNotInTimeWindow",
    "UsmUnknownUserName",
    "UnknownEngineID",
    "UsmWrongDigest",
    "UsmDecryptionError",
    "ReportMessage",
]

from snmp.typing import Optional
from snmp.utils import subbytes

class SNMPException(Exception):
    """Base class for all run-time exceptions in this library."""

class SNMPLibraryBug(AssertionError):
    """Base class for logic errors in the code of this library."""

class UnsupportedFeature(SNMPLibraryBug):
    """A failure owing to a feature that this library does not yet support."""

class IncomingMessageError(SNMPException):
    """An error indicating a received message is invalid in some way."""

class IncomingMessageErrorWithPointer(IncomingMessageError):
    def __init__(self,
        msg: str,
        data: subbytes,
        tail: Optional[subbytes] = None,
    ) -> None:
        super().__init__(msg)

        if tail is None:
            self.data = data
        else:
            self.data = subbytes(data, stop=len(data) - len(tail))

class AuthenticationNotEnabled(SNMPException):
    pass

class PrivacyNotEnabled(SNMPException):
    pass

class EncodeError(SNMPException):
    pass

class InvalidSignature(IncomingMessageError):
    pass

# USM Stats Errors

class UsmUnsupportedSecLevel(IncomingMessageError):
    def __init__(self, level=None):
        if level is None:
            errmsg = f"The remote engine does not support" \
                " the requested securityLevel"
        else:
            errmsg = f"The remote engine does not support {level}"

        super().__init__(errmsg)

class UsmNotInTimeWindow(IncomingMessageError):
    pass

class UsmUnknownUserName(IncomingMessageError):
    def __init__(self, username=None):
        if username is None:
            errmsg = "The remote engine does not recognize the requested user"
        else:
            errmsg = f'The remote engine does not recognize user "{username}"'

        super().__init__(errmsg)

class UnknownEngineID(IncomingMessageError):
    pass

class UsmWrongDigest(IncomingMessageError):
    def __init__(self, username=None):
        errmsg = "The remote engine reported an incorrect message signature"

        if username is not None:
            errmsg += f"; check that \"{username}\" is using" \
                " the right authentication protocol and secret"

        super().__init__(errmsg)

class UsmDecryptionError(IncomingMessageError):
    def __init__(self, username=None):
        errmsg = "The remote engine was not able to decrypt the message"

        if username is not None:
            errmsg += f"; check that \"{username}\" is using" \
                " the right privacy protocol and secret"

        super().__init__(errmsg)



class ReportMessage(SNMPException):
    def __init__(self, message):
        self.message = message
